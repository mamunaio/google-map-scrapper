"""
LeadHunter RQ Background Job Tasks.
Executes Google Maps scraping and website intelligence enrichment inside an isolated
RQ worker process, completely decoupled from Flask HTTP request threads.
"""

import logging
from datetime import datetime, timezone

from services.email_verifier import verify_email_batch
from services.maps_scraper import (
    clean_external_website_url,
    ensure_english_maps_url,
    scrape_google_maps,
)
from services.runtime_config import job_id_var, redact_email_for_log, redact_url_for_log
from services.security import SecurityError, validate_and_sanitize_url, validate_google_maps_url
from services.website_crawler import crawl_and_audit_website

logger = logging.getLogger("leadhunter.worker")


def _update_job_progress(
    stage: str,
    progress_pct: int,
    processed: int = 0,
    total: int = 0,
    message: str = "",
    extra_meta: dict | None = None,
):
    """Updates live progress metadata on the active RQ job when executing inside a worker."""
    try:
        from rq import get_current_job

        job = get_current_job()
        if job is not None:
            payload = {
                "stage": stage,
                "progress_pct": max(0, min(100, int(progress_pct))),
                "processed_leads": int(processed),
                "total_leads": int(total),
                "message": message,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            if extra_meta:
                payload.update(extra_meta)
            job.meta.update(payload)
            job.save_meta()
    except Exception:
        pass


def execute_scrape_job(
    url: str,
    scrape_type: str = "website",
    max_results: int = 20,
    business_name: str = "",
    decision_maker: str = "",
) -> dict:
    """
    Isolated background task executed by RQ workers.
    - Non-retryable `SecurityError` is returned as a structured terminal failure payload
      (HTTP 400 equivalent) so RQ does not waste retries on blocked SSRF targets.
    - Unexpected operational exceptions propagate so RQ applies its bounded `Retry` policy.
    """
    current_jid = "-"
    try:
        from rq import get_current_job

        cur = get_current_job()
        if cur is not None:
            current_jid = cur.id
    except Exception:
        pass

    token = job_id_var.set(current_jid)
    try:
        safe_log_url = redact_url_for_log(url)
        logger.info("Job started: type=%s max_results=%d target=%s", scrape_type, max_results, safe_log_url)
        _update_job_progress("validating", 5, 0, 0, "Validating target URL")

        if scrape_type == "maps":
            try:
                clean_url = ensure_english_maps_url(validate_google_maps_url(url))
            except SecurityError as se:
                logger.warning("Job blocked by security policy for %s: %s", safe_log_url, se)
                _update_job_progress("blocked", 100, 0, 0, "Blocked by security policy")
                return {
                    "success": False,
                    "http_status": 400,
                    "error": f"Security restriction: {se}",
                    "is_search": False,
                    "leads": [],
                    "count": 0,
                    "data": None,
                }

            _update_job_progress("scraping_maps", 15, 0, max_results, "Extracting Google Maps listings")
            maps_res = scrape_google_maps(clean_url, max_results=max_results)

            if not maps_res.get("success"):
                logger.warning("Maps extraction returned no listings for %s", safe_log_url)
                _update_job_progress("completed_empty", 100, 0, 0, "No listings extracted")
                return {
                    "success": False,
                    "http_status": 422,
                    "error": maps_res.get(
                        "error",
                        "No business details or listings could be extracted from this Google Maps URL.",
                    ),
                    "is_search": maps_res.get("is_search", False),
                    "leads": [],
                    "count": 0,
                    "data": None,
                }

            extracted_leads = maps_res.get("leads", [])
            total_leads = len(extracted_leads)
            enriched_leads: list[dict] = []
            logger.info("Extracted %d Maps listing(s); starting website enrichment", total_leads)

            for idx, raw_lead in enumerate(extracted_leads, 1):
                lead = dict(raw_lead)
                if business_name and not lead.get("Business Name"):
                    lead["Business Name"] = business_name

                biz_label = lead.get("Business Name") or f"Listing #{idx}"
                clean_website = clean_external_website_url(lead.get("Website") or "")
                lead["Website"] = clean_website

                pct = 20 + int((idx - 1) / max(1, total_leads) * 75)
                _update_job_progress(
                    "enriching",
                    pct,
                    idx - 1,
                    total_leads,
                    f"Auditing business {idx} of {total_leads}",
                )

                if clean_website:
                    try:
                        audit_data = crawl_and_audit_website(
                            clean_website,
                            hint_decision_maker=decision_maker,
                            business_name=lead.get("Business Name", ""),
                            phone=lead.get("Phone") or lead.get("Phone Number") or "",
                        )
                        lead["Website"] = audit_data.get("Website", clean_website)
                        lead["Website Status"] = audit_data.get("Website Status", "Online")
                        lead["Email"] = audit_data.get("Email", "")
                        lead["Contact Person"] = audit_data.get("Contact Person") or audit_data.get("Decision Maker", "")
                        lead["Decision Maker"] = audit_data.get("Decision Maker", "")
                        lead["Email Status"] = audit_data.get("Email Status") or audit_data.get("Email Verification", "Not Found")
                        lead["Email Verification"] = audit_data.get("Email Verification", "Not Found")
                        lead["Facebook"] = audit_data.get("Facebook", "")
                        lead["Instagram"] = audit_data.get("Instagram", "")
                        lead["LinkedIn"] = audit_data.get("LinkedIn", "")
                        lead["About Page Link"] = audit_data.get("About Page Link", "")
                        lead["intelligence"] = audit_data.get("intelligence")

                        intel = audit_data.get("intelligence") or {}
                        opps = intel.get("opportunities") or {}
                        scoring = opps.get("scoring_details") or {}
                        lead["Priority"] = audit_data.get("Priority") or opps.get("priority") or "Manual Review"
                        lead["Lead Score"] = (
                            audit_data.get("Lead Score")
                            if audit_data.get("Lead Score") is not None
                            else (opps.get("lead_score") or 0)
                        )
                        lead["Main Opportunity"] = audit_data.get("Main Opportunity") or opps.get("main_gap") or ""
                        lead["Notes"] = audit_data.get("Notes") or scoring.get("priority_reason") or ""
                        logger.info(
                            "Enriched %d/%d '%s' (email=%s priority=%s)",
                            idx,
                            total_leads,
                            biz_label,
                            redact_email_for_log(lead["Email"]),
                            lead["Priority"],
                        )
                    except Exception as exc:
                        logger.warning(
                            "Enrichment failed for %d/%d '%s' (%s): %s",
                            idx,
                            total_leads,
                            biz_label,
                            redact_url_for_log(clean_website),
                            exc,
                        )
                        lead.setdefault("Website Status", "Crawl failed")
                        lead.setdefault("Priority", "Manual Review")
                        lead.setdefault("Lead Score", 0)
                        lead.setdefault("Main Opportunity", "Website inspection failed — manual review required")
                        lead.setdefault("Notes", "Website audit failed — manual review required.")
                else:
                    lead.setdefault("Website Status", "Not checked")
                    lead.setdefault("Priority", "Manual Review")
                    lead.setdefault("Lead Score", 0)
                    lead.setdefault("Main Opportunity", "No website provided — manual review required")
                    lead.setdefault("Notes", "No valid external website available for automated audit.")

                enriched_leads.append(lead)

            _update_job_progress("completed", 100, total_leads, total_leads, f"Completed {total_leads} leads")
            logger.info("Job completed: %d lead(s) processed for %s", len(enriched_leads), safe_log_url)
            return {
                "success": True,
                "http_status": 200,
                "is_search": maps_res.get("is_search", False),
                "leads": enriched_leads,
                "count": len(enriched_leads),
                "data": enriched_leads[0] if enriched_leads else None,
            }

        elif scrape_type == "website":
            try:
                validate_and_sanitize_url(url)
            except SecurityError as se:
                logger.warning("Job blocked by security policy for %s: %s", safe_log_url, se)
                _update_job_progress("blocked", 100, 0, 1, "Blocked by security policy")
                return {
                    "success": False,
                    "http_status": 400,
                    "error": f"Security restriction: {se}",
                    "is_search": False,
                    "leads": [],
                    "count": 0,
                    "data": None,
                }

            _update_job_progress("auditing_website", 35, 0, 1, "Auditing website")
            result = {
                "Business Name": business_name,
                "Category": "Unknown",
                "City": "Unknown",
                "State": "Unknown",
                "Phone": "",
                "Phone Number": "",
                "Website": url,
                "Google Maps URL": "",
                "Rating": None,
                "Reviews": None,
                "Contact Person": "",
                "Decision Maker": "",
                "Email": "",
                "Email Status": "Not Found",
                "Email Verification": "Not Found",
                "Priority": "Manual Review",
                "Lead Score": 0,
                "Main Opportunity": "",
                "Notes": "",
                "Facebook": "",
                "Instagram": "",
                "LinkedIn": "",
                "About Page Link": "",
                "Source URL": url,
                "intelligence": None,
            }

            audit_data = crawl_and_audit_website(
                url,
                hint_decision_maker=decision_maker,
                business_name=result["Business Name"],
            )

            result["Website"] = audit_data.get("Website", url)
            result["Website Status"] = audit_data.get("Website Status", "Online")
            result["Email"] = audit_data.get("Email", "")
            result["Contact Person"] = audit_data.get("Contact Person") or audit_data.get("Decision Maker", "")
            result["Decision Maker"] = audit_data.get("Decision Maker", "")
            result["Email Status"] = audit_data.get("Email Status") or audit_data.get("Email Verification", "Not Found")
            result["Email Verification"] = audit_data.get("Email Verification", "Not Found")
            result["Facebook"] = audit_data.get("Facebook", "")
            result["Instagram"] = audit_data.get("Instagram", "")
            result["LinkedIn"] = audit_data.get("LinkedIn", "")
            result["About Page Link"] = audit_data.get("About Page Link", "")
            result["intelligence"] = audit_data.get("intelligence")

            intel = audit_data.get("intelligence") or {}
            opps = intel.get("opportunities") or {}
            scoring = opps.get("scoring_details") or {}
            result["Priority"] = audit_data.get("Priority") or opps.get("priority") or "Manual Review"
            result["Lead Score"] = (
                audit_data.get("Lead Score")
                if audit_data.get("Lead Score") is not None
                else (opps.get("lead_score") or 0)
            )
            result["Main Opportunity"] = audit_data.get("Main Opportunity") or opps.get("main_gap") or ""
            result["Notes"] = audit_data.get("Notes") or scoring.get("priority_reason") or ""

            _update_job_progress("completed", 100, 1, 1, "Website audit complete")
            logger.info(
                "Website job completed for %s (email=%s priority=%s)",
                safe_log_url,
                redact_email_for_log(result["Email"]),
                result["Priority"],
            )
            return {
                "success": True,
                "http_status": 200,
                "is_search": False,
                "leads": [result],
                "count": 1,
                "data": result,
            }

        raise ValueError(f"Unsupported scrape_type: {scrape_type}")
    finally:
        job_id_var.reset(token)


def execute_email_verification_batch_job(
    items: list[dict],
    provider_name: str | None = None,
) -> dict:
    """
    Isolated RQ background task for batch email verification.
    - Deduplicates normalized emails within the batch so identical addresses are checked once.
    - Never logs raw email addresses (PII-safe).
    - Publishes live `processed_count`, `remaining_count`, `total_count`, and per-status `counts`
      (`Valid`, `Risky`, `Invalid`, `Unknown`) to `job.meta`.
    """
    current_jid = "-"
    try:
        from rq import get_current_job

        cur = get_current_job()
        if cur is not None:
            current_jid = cur.id
    except Exception:
        pass

    token = job_id_var.set(current_jid)
    try:
        total = len(items or [])
        logger.info("Email verification batch job started: total_items=%d", total)
        initial_counts = {"Valid": 0, "Risky": 0, "Invalid": 0, "Unknown": 0}
        _update_job_progress(
            "verifying_emails",
            0 if total > 0 else 100,
            0,
            total,
            f"Starting verification for {total} email(s)",
            extra_meta={
                "job_type": "email_verification",
                "processed_count": 0,
                "remaining_count": total,
                "total_count": total,
                "counts": initial_counts,
            },
        )

        def on_progress(processed: int, total_items: int, counts: dict[str, int]):
            remaining = max(0, total_items - processed)
            pct = int(round((processed / max(1, total_items)) * 100))
            _update_job_progress(
                "verifying_emails",
                min(99, pct) if remaining > 0 else 100,
                processed,
                total_items,
                f"Verified {processed} of {total_items} email(s) ({remaining} remaining)",
                extra_meta={
                    "job_type": "email_verification",
                    "processed_count": processed,
                    "remaining_count": remaining,
                    "total_count": total_items,
                    "counts": dict(counts),
                },
            )

        summary = verify_email_batch(
            items or [],
            provider_name=provider_name,
            progress_callback=on_progress,
        )

        _update_job_progress(
            "completed",
            100,
            summary["processed"],
            summary["total"],
            f"Verified {summary['processed']} of {summary['total']} email(s)",
            extra_meta={
                "job_type": "email_verification",
                "processed_count": summary["processed"],
                "remaining_count": 0,
                "total_count": summary["total"],
                "counts": dict(summary["counts"]),
            },
        )
        logger.info(
            "Email verification batch job completed: total=%d unique=%d counts=%s",
            summary["total"],
            summary["unique_checked"],
            summary["counts"],
        )
        return {
            "success": True,
            "http_status": 200,
            "job_type": "email_verification",
            "total": summary["total"],
            "processed": summary["processed"],
            "remaining": 0,
            "unique_checked": summary["unique_checked"],
            "duplicates_suppressed": summary["duplicates_suppressed"],
            "counts": summary["counts"],
            "provider": summary["provider"],
            "results": summary["results"],
        }
    finally:
        job_id_var.reset(token)
