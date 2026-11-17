import unittest
from services.business_feature_detector import detect_business_features

class TestBusinessFeatureDetector(unittest.TestCase):
    def test_booking_detection(self):
        html = """
        <html>
        <body>
            <h1>Book an Appointment</h1>
            <script src="https://assets.calendly.com/assets/external/widget.js"></script>
            <a href="https://calendly.com/acme/consult">Schedule Online</a>
        </body>
        </html>
        """
        feats = detect_business_features(html)
        self.assertEqual(feats["booking"]["status"], "Detected")
        self.assertIn("Calendly", feats["booking"]["providers"])

    def test_chatbot_detection(self):
        html = """
        <html>
        <head>
            <script src="//code.tidio.co/abcdefg123456.js" async></script>
        </head>
        <body>
            <p>Hello world</p>
        </body>
        </html>
        """
        feats = detect_business_features(html)
        self.assertEqual(feats["chatbot"]["status"], "Detected")
        self.assertIn("Tidio", feats["chatbot"]["providers"])

    def test_crm_and_analytics_detection(self):
        html = """
        <html>
        <head>
            <!-- Google Tag Manager -->
            <script src="https://www.googletagmanager.com/gtm.js?id=GTM-XXXXXX"></script>
            <!-- HubSpot Embed Code -->
            <script type="text/javascript" id="hs-script-loader" async defer src="//js.hs-scripts.com/1234567.js"></script>
        </head>
        <body></body>
        </html>
        """
        feats = detect_business_features(html)
        self.assertEqual(feats["crm"]["status"], "Detected")
        self.assertIn("HubSpot", feats["crm"]["providers"])
        self.assertEqual(feats["analytics"]["status"], "Detected")
        self.assertIn("Google Tag Manager", feats["analytics"]["providers"])

    def test_lead_capture_form_and_tel_detection(self):
        html = """
        <html>
        <body>
            <a href="tel:5551234567">Call (555) 123-4567</a>
            <form action="/submit-quote" method="POST">
                <input type="text" name="name" />
                <input type="email" name="email" />
                <button type="submit">Get Free Quote</button>
            </form>
        </body>
        </html>
        """
        feats = detect_business_features(html)
        self.assertEqual(feats["lead_capture"]["status"], "Detected")
        self.assertTrue(feats["lead_capture"]["details"]["has_quote_form"])
        self.assertTrue(feats["lead_capture"]["details"]["has_phone_link"])

    def test_empty_html_handling(self):
        feats = detect_business_features("")
        self.assertEqual(feats["booking"]["status"], "Scan Failed")

if __name__ == '__main__':
    unittest.main()
