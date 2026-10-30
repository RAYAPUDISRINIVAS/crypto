import os
from unittest.mock import patch

from django.test import SimpleTestCase


class DatabaseUnavailableTests(SimpleTestCase):
    def test_login_returns_service_unavailable_when_database_url_is_missing(self):
        with patch.dict(os.environ, {"DATABASE_URL": ""}):
            response = self.client.post(
                "/login/",
                {"t1": "test_user", "t2": "Disposable-Test-123!"},
                HTTP_HOST="localhost",
            )

        self.assertEqual(response.status_code, 503)
        self.assertContains(response, "Login is temporarily unavailable", status_code=503)

    def test_signup_returns_service_unavailable_when_database_url_is_missing(self):
        with patch.dict(os.environ, {"DATABASE_URL": ""}):
            response = self.client.post(
                "/signup/",
                {
                    "t1": "test_user",
                    "t2": "Strong-Test-123!",
                    "t3": "1234567890",
                    "t4": "test@example.com",
                    "t5": "123 Test Street",
                },
                HTTP_HOST="localhost",
            )

        self.assertEqual(response.status_code, 503)
        self.assertContains(response, "Signup is temporarily unavailable", status_code=503)
