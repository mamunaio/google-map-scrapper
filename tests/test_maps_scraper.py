import unittest
from unittest.mock import MagicMock, patch
from services.maps_scraper import (
    is_maps_search_url,
    normalize_place_url,
    clean_google_redirect_url,
    extract_search_listing_card,
    scrape_maps_search_feed,
    scrape_maps_place_detail,
    scrape_google_maps
)

class TestMapsScraper(unittest.TestCase):

    def test_is_maps_search_url_detection(self):
        # Search URLs
        self.assertTrue(is_maps_search_url("https://www.google.com/maps/search/HVAC+contractors+in+Dallas,+TX"))
        self.assertTrue(is_maps_search_url("https://www.google.com/maps/search/?api=1&query=Plumbers"))
        self.assertTrue(is_maps_search_url("https://maps.google.com/?q=roofing+contractors+chicago"))
        self.assertTrue(is_maps_search_url("https://www.google.com/maps/search/dentists/data=!3m1!4b1"))

        # Non-Search / Place URLs
        self.assertFalse(is_maps_search_url("https://www.google.com/maps/place/Dallas+HVAC/@32.7767,-96.7970,14z/data=!4m6!3m5!1s0x0:0x12345"))
        self.assertFalse(is_maps_search_url("https://maps.google.com/maps/place/Texas+Heating+and+Air"))
        self.assertFalse(is_maps_search_url("https://example.com/search?q=hvac"))
        self.assertFalse(is_maps_search_url(""))
        self.assertFalse(is_maps_search_url(None))

    def test_normalize_place_url(self):
        raw = "https://www.google.com/maps/place/Dallas+HVAC/@32.7767,-96.7970,14z/?entry=ttu&g_ep=CAESCTExLjE%3D"
        normalized = normalize_place_url(raw)
        self.assertEqual(normalized, "www.google.com/maps/place/dallas+hvac/@32.7767,-96.7970,14z")

        # Edge cases
        self.assertEqual(normalize_place_url(""), "")
        self.assertEqual(normalize_place_url(None), "")

    def test_clean_google_redirect_url(self):
        redirect = "/url?q=https%3A%2F%2Fwww.dallashvacpros.com%2F&sa=U&ved=0ahUKEwi..."
        target = clean_google_redirect_url(redirect)
        self.assertEqual(target, "https://www.dallashvacpros.com/")

        direct = "https://www.dallashvacpros.com/"
        self.assertEqual(clean_google_redirect_url(direct), direct)
        self.assertEqual(clean_google_redirect_url(""), "")

    def test_extract_search_listing_card_full(self):
        card = MagicMock()

        # Name
        name_mock = MagicMock()
        name_mock.count.return_value = 1
        name_mock.inner_text.return_value = "Dallas Pro HVAC"

        # Place Link
        link_mock = MagicMock()
        link_mock.count.return_value = 1
        link_mock.first.get_attribute.return_value = "https://www.google.com/maps/place/Dallas+Pro+HVAC/data=!123"

        # Website
        web_mock = MagicMock()
        web_mock.count.return_value = 1
        web_mock.first.get_attribute.return_value = "/url?q=https%3A%2F%2Fdallasprohvac.com%2F"

        # Rating
        rating_mock = MagicMock()
        rating_mock.count.return_value = 1
        rating_mock.inner_text.return_value = "4.9"

        # Reviews
        rev_mock = MagicMock()
        rev_mock.count.return_value = 1
        rev_mock.inner_text.return_value = "(185)"

        def locator_side_effect(selector):
            if 'div.qBF1Pd' in selector:
                return name_mock
            elif 'a.hfpxzc' in selector:
                return link_mock
            elif 'a.lcr4fd' in selector or 'Website' in selector:
                return web_mock
            elif 'span.MW4etd' in selector:
                return rating_mock
            elif 'span.UY7F9' in selector:
                return rev_mock
            m = MagicMock()
            m.count.return_value = 0
            return m

        card.locator.side_effect = locator_side_effect
        card.inner_text.return_value = "Dallas Pro HVAC\n4.9(185) · HVAC contractor\n(214) 555-0199\nOpen 24 hours"

        lead = extract_search_listing_card(card)
        self.assertIsNotNone(lead)
        self.assertEqual(lead["Business Name"], "Dallas Pro HVAC")
        self.assertEqual(lead["Phone Number"], "(214) 555-0199")
        self.assertEqual(lead["Website"], "https://dallasprohvac.com/")
        self.assertEqual(lead["Rating"], "4.9")
        self.assertEqual(lead["Review Count"], "185")
        self.assertEqual(lead["Google Maps Profile"], "https://www.google.com/maps/place/Dallas+Pro+HVAC/data=!123")

    def test_extract_search_listing_card_missing_optional_fields(self):
        card = MagicMock()

        name_mock = MagicMock()
        name_mock.count.return_value = 1
        name_mock.inner_text.return_value = "Lone Star Heating"

        empty_mock = MagicMock()
        empty_mock.count.return_value = 0

        def locator_side_effect(selector):
            if 'div.qBF1Pd' in selector:
                return name_mock
            return empty_mock

        card.locator.side_effect = locator_side_effect
        card.inner_text.return_value = "Lone Star Heating\nNo phone available"

        lead = extract_search_listing_card(card)
        self.assertIsNotNone(lead)
        self.assertEqual(lead["Business Name"], "Lone Star Heating")
        self.assertEqual(lead["Phone Number"], "")
        self.assertEqual(lead["Website"], "")
        self.assertEqual(lead["Rating"], "")
        self.assertEqual(lead["Review Count"], "")

    def test_scrape_maps_search_feed_multiple_and_deduplication(self):
        page = MagicMock()

        # Build 3 mock cards (card 1 and card 3 are identical duplicates)
        def create_mock_card(name, phone, place_url):
            c = MagicMock()
            name_m = MagicMock()
            name_m.count.return_value = 1
            name_m.inner_text.return_value = name

            link_m = MagicMock()
            link_m.count.return_value = 1
            link_m.first.get_attribute.return_value = place_url

            def loc(sel):
                if 'div.qBF1Pd' in selector:
                    return name_m
                if 'a.hfpxzc' in selector:
                    return link_m
                m = MagicMock()
                m.count.return_value = 0
                return m

            # Python scoping workaround for closure
            def make_loc(n_m, l_m):
                def _loc(sel):
                    if 'div.qBF1Pd' in sel:
                        return n_m
                    if 'a.hfpxzc' in sel:
                        return l_m
                    m = MagicMock()
                    m.count.return_value = 0
                    return m
                return _loc

            c.locator.side_effect = make_loc(name_m, link_m)
            c.inner_text.return_value = f"{name}\n{phone}"
            return c

        card1 = create_mock_card("Alpha HVAC", "(214) 555-0101", "https://maps.google.com/place/alpha")
        card2 = create_mock_card("Beta Air", "(214) 555-0102", "https://maps.google.com/place/beta")
        card3 = create_mock_card("Alpha HVAC", "(214) 555-0101", "https://maps.google.com/place/alpha") # duplicate

        cards_mock = MagicMock()
        cards_mock.all.return_value = [card1, card2, card3]

        feed_mock = MagicMock()
        feed_mock.count.return_value = 0  # No scrolling loop

        def page_loc(sel):
            if 'div.Nv2PK' in sel:
                return cards_mock
            if 'div[role="feed"]' in sel:
                return feed_mock
            m = MagicMock()
            m.count.return_value = 0
            return m

        page.locator.side_effect = page_loc

        leads = scrape_maps_search_feed(page, max_results=10)
        self.assertEqual(len(leads), 2)
        self.assertEqual(leads[0]["Business Name"], "Alpha HVAC")
        self.assertEqual(leads[1]["Business Name"], "Beta Air")

    def test_scrape_maps_place_detail(self):
        page = MagicMock()

        name_mock = MagicMock()
        name_mock.count.return_value = 1
        name_mock.first.inner_text.return_value = "Dallas Master Heating"

        web_mock = MagicMock()
        web_mock.count.return_value = 1
        web_mock.first.get_attribute.return_value = "/url?q=https%3A%2F%2Fdallasheating.com"

        phone_mock = MagicMock()
        phone_mock.count.return_value = 1
        phone_mock.first.inner_text.return_value = "(214) 555-9988"

        rating_mock = MagicMock()
        rating_mock.count.return_value = 1
        rating_mock.first.inner_text.return_value = "4.8"

        rev_mock = MagicMock()
        rev_mock.count.return_value = 1
        rev_mock.first.inner_text.return_value = "(320)"

        def loc(sel):
            if 'h1.DUwDvf' in sel:
                return name_mock
            if 'authority' in sel:
                return web_mock
            if 'phone' in sel:
                return phone_mock
            if 'F7nice span[aria-hidden="true"]' in sel:
                return rating_mock
            if 'review' in sel:
                return rev_mock
            m = MagicMock()
            m.count.return_value = 0
            return m

        page.locator.side_effect = loc

        lead = scrape_maps_place_detail(page, "https://www.google.com/maps/place/Dallas+Master+Heating")
        self.assertEqual(lead["Business Name"], "Dallas Master Heating")
        self.assertEqual(lead["Website"], "https://dallasheating.com")
        self.assertEqual(lead["Phone Number"], "(214) 555-9988")
        self.assertEqual(lead["Rating"], "4.8")
        self.assertEqual(lead["Review Count"], "320")

    @patch('services.maps_scraper.sync_playwright')
    def test_scrape_google_maps_search_url_honest_success(self, mock_playwright):
        # Mock Playwright browser, context, page
        mock_p = MagicMock()
        mock_playwright.return_value.__enter__.return_value = mock_p
        mock_browser = MagicMock()
        mock_p.chromium.launch.return_value = mock_browser
        mock_context = MagicMock()
        mock_browser.new_context.return_value = mock_context
        mock_page = MagicMock()
        mock_context.new_page.return_value = mock_page

        with patch('services.maps_scraper.scrape_maps_search_feed') as mock_feed:
            mock_feed.return_value = [
                {"Business Name": "Biz 1", "Website": "https://biz1.com", "Phone Number": "214-555-01"},
                {"Business Name": "Biz 2", "Website": "https://biz2.com", "Phone Number": "214-555-02"}
            ]

            result = scrape_google_maps("https://www.google.com/maps/search/HVAC+contractors+in+Dallas,+TX")

            self.assertTrue(result["success"])
            self.assertTrue(result["is_search"])
            self.assertEqual(result["count"], 2)
            self.assertEqual(len(result["leads"]), 2)
            self.assertEqual(result["data"]["Business Name"], "Biz 1")

    @patch('services.maps_scraper.sync_playwright')
    def test_scrape_google_maps_search_url_honest_empty_failure(self, mock_playwright):
        mock_p = MagicMock()
        mock_playwright.return_value.__enter__.return_value = mock_p
        mock_browser = MagicMock()
        mock_p.chromium.launch.return_value = mock_browser
        mock_context = MagicMock()
        mock_browser.new_context.return_value = mock_context
        mock_page = MagicMock()
        mock_context.new_page.return_value = mock_page

        with patch('services.maps_scraper.scrape_maps_search_feed') as mock_feed:
            mock_feed.return_value = []

            result = scrape_google_maps("https://www.google.com/maps/search/HVAC+contractors+in+Dallas,+TX")

            self.assertFalse(result["success"])
            self.assertTrue(result["is_search"])
            self.assertEqual(result["count"], 0)
            self.assertEqual(result["leads"], [])
            self.assertIn("No business listings found", result["error"])

    @patch('services.maps_scraper.sync_playwright')
    def test_scrape_google_maps_place_url_empty_honest_failure(self, mock_playwright):
        mock_p = MagicMock()
        mock_playwright.return_value.__enter__.return_value = mock_p
        mock_browser = MagicMock()
        mock_p.chromium.launch.return_value = mock_browser
        mock_context = MagicMock()
        mock_browser.new_context.return_value = mock_context
        mock_page = MagicMock()
        mock_context.new_page.return_value = mock_page

        with patch('services.maps_scraper.scrape_maps_place_detail') as mock_detail:
            mock_detail.return_value = {"Business Name": "", "Website": "", "Phone Number": ""}

            result = scrape_google_maps("https://www.google.com/maps/place/Empty+Location")

            self.assertFalse(result["success"])
            self.assertFalse(result["is_search"])
            self.assertEqual(result["count"], 0)
            self.assertEqual(result["leads"], [])
            self.assertIsNone(result["data"])
            self.assertIn("No business details found", result["error"])

    def test_playwright_and_proxy_lifecycle_sequence(self):
        """
        Verify that:
        1. SafeBrowserProxy starts before Playwright launches.
        2. Navigation (page.goto) and data extraction happen WHILE Playwright context is active.
        3. Browser, context, and page are closed while Playwright is still active.
        4. Playwright context exits before SafeBrowserProxy stops.
        5. Browser closes BEFORE SafeBrowserProxy stops.
        """
        events = []

        class MockProxyContext:
            def __enter__(self):
                events.append("proxy_enter")
                mock_p = MagicMock()
                mock_p.port = 12345
                return mock_p
            def __exit__(self, exc_type, exc_val, exc_tb):
                events.append("proxy_exit")

        mock_page = MagicMock()
        mock_context = MagicMock()
        mock_browser = MagicMock()

        def record_page_goto(*args, **kwargs):
            events.append("page_goto")

        def record_page_close(*args, **kwargs):
            events.append("page_close")

        def record_context_close(*args, **kwargs):
            events.append("context_close")

        def record_browser_close(*args, **kwargs):
            events.append("browser_close")

        mock_page.goto.side_effect = record_page_goto
        mock_page.close.side_effect = record_page_close
        mock_context.close.side_effect = record_context_close
        mock_browser.close.side_effect = record_browser_close

        mock_context.new_page.return_value = mock_page
        mock_browser.new_context.return_value = mock_context

        class MockPlaywrightContext:
            def __enter__(self):
                events.append("playwright_enter")
                mock_play = MagicMock()
                mock_play.chromium.launch.return_value = mock_browser
                return mock_play
            def __exit__(self, exc_type, exc_val, exc_tb):
                events.append("playwright_exit")

        def record_search_feed(*args, **kwargs):
            events.append("search_feed")
            return [{"Business Name": "Test HVAC", "Website": "https://testhvac.com"}]

        with patch('services.maps_scraper.SafeBrowserProxy', side_effect=MockProxyContext), \
             patch('services.maps_scraper.sync_playwright', side_effect=MockPlaywrightContext), \
             patch('services.maps_scraper.scrape_maps_search_feed', side_effect=record_search_feed):

            res = scrape_google_maps("https://www.google.com/maps/search/HVAC+contractors+in+Dallas,+TX")
            self.assertTrue(res["success"])

        # Validate complete ordered lifecycle:
        # proxy_enter -> playwright_enter -> page_goto -> search_feed -> page_close -> context_close -> browser_close -> playwright_exit -> proxy_exit
        self.assertEqual(events, [
            "proxy_enter",
            "playwright_enter",
            "page_goto",
            "search_feed",
            "page_close",
            "context_close",
            "browser_close",
            "playwright_exit",
            "proxy_exit"
        ])

        # Explicit assertion checks
        p_enter = events.index("playwright_enter")
        p_exit = events.index("playwright_exit")
        goto_idx = events.index("page_goto")
        feed_idx = events.index("search_feed")
        b_close_idx = events.index("browser_close")
        proxy_exit_idx = events.index("proxy_exit")

        self.assertLess(p_enter, goto_idx, "page.goto must occur inside Playwright context")
        self.assertLess(goto_idx, p_exit, "page.goto must occur before Playwright exits")
        self.assertLess(p_enter, feed_idx, "Extraction must occur inside Playwright context")
        self.assertLess(feed_idx, p_exit, "Extraction must occur before Playwright exits")
        self.assertLess(b_close_idx, p_exit, "Browser must close before Playwright exits")
        self.assertLess(b_close_idx, proxy_exit_idx, "Browser must close before SafeBrowserProxy stops")
        self.assertLess(p_exit, proxy_exit_idx, "Playwright must exit before SafeBrowserProxy stops")

if __name__ == '__main__':
    unittest.main()
