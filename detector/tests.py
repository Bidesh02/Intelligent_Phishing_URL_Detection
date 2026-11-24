import json
from django.test import TestCase, Client
from django.urls import reverse
from .models import ScanHistory
from .feature_extractor import predict_url, extract_features

class PhishingDetectorTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_feature_extractor(self):
        url = "https://www.google.com"
        features, indicators, summary = extract_features(url)
        self.assertEqual(summary["is_https"], True)
        self.assertEqual(summary["is_ip"], False)
        self.assertIn("URLLength", features)
        self.assertEqual(len(features), 50)

    def test_ip_address_detection(self):
        url = "http://192.168.1.1/login.php"
        features, indicators, summary = extract_features(url)
        self.assertEqual(summary["is_https"], False)
        self.assertEqual(summary["is_ip"], True)

    def test_prediction_legitimate(self):
        res = predict_url("https://www.google.com")
        self.assertIn("prediction", res)
        self.assertIn("confidence", res)
        self.assertIn("indicators", res)

    def test_prediction_phishing(self):
        res = predict_url("http://192.168.1.100/paypal/login.php?verify=1")
        self.assertIn("prediction", res)
        self.assertEqual(res["is_phishing"], True)

    def test_index_view_get(self):
        response = self.client.get(reverse('index'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Real-Time")

    def test_index_view_post(self):
        response = self.client.post(reverse('index'), {'url': 'https://github.com'})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "github.com")
        self.assertEqual(ScanHistory.objects.count(), 1)

    def test_api_scan_endpoint(self):
        payload = json.dumps({'url': 'http://192.168.1.100/paypal/login.php?verify=1'})
        response = self.client.post(
            reverse('api_scan'),
            data=payload,
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['status'], 'success')
        self.assertIn('data', data)
        self.assertEqual(data['data']['is_phishing'], True)

    def test_history_and_analytics_views(self):
        resp_history = self.client.get(reverse('history'))
        self.assertEqual(resp_history.status_code, 200)

        resp_analytics = self.client.get(reverse('analytics'))
        self.assertEqual(resp_analytics.status_code, 200)
