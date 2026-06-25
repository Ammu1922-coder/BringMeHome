import os
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings


class GeminiChatFallbackTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username='assistant-user', password='secret123')

    @override_settings(GOOGLE_API_KEY='')
    def test_gemini_chat_returns_local_reply_without_api_key(self):
        self.client.force_login(self.user)

        with patch.dict(os.environ, {'GOOGLE_API_KEY': ''}, clear=False):
            response = self.client.post(
                '/gemini-chat/',
                data={'question': 'How does this website work?', 'language': 'Telugu'},
                content_type='application/json',
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn('reply', payload)
        self.assertTrue(payload['reply'])
