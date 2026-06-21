# Smart Web & Google Maps Scraper

A lightweight, powerful web application built with **Python Flask** and **Playwright** to scrape Google Maps links and enrich Excel/CSV files with business contact details (Email, Facebook, Instagram, LinkedIn, and About Page links).

## Features
- **Option A (Manual Input):** Paste Google Maps URLs to extract Business Name, Website, Phone, and social/email links.
- **Option B (File Upload):** Upload an existing Excel or CSV file. The tool automatically detects the "Website" column, visits the websites, and enriches your file with contact details.
- **Live Progress:** Real-time progress bar and logs on the frontend.
- **Smart Formatting:** Exports results in a beautifully formatted `.xlsx` (Excel) file.

## Requirements
- Python 3.10+
- Playwright Chromium

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/mamunaio/google-map-scrapper.git
   cd google-map-scrapper
   ```

2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Install Playwright browser:
   ```bash
   python -m playwright install chromium
   ```

## Usage

1. Start the Flask server:
   ```bash
   python app.py
   ```

2. Open your browser and go to `http://localhost:5000`

## Tech Stack
- **Backend:** Python, Flask, Playwright, BeautifulSoup4, Requests
- **Frontend:** HTML5, Tailwind CSS, PapaParse, SheetJS (XLSX)

## Warning & Ethics
This tool is built for educational purposes and data enrichment. Please be aware of the Terms of Service of any websites you scrape and do not overload servers. The script includes randomized delays to behave respectfully.
