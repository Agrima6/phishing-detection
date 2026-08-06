"""
Configuration for Phishing Awareness Dashboard – Containerised Flask App
"""

import os


class Config:
    def __init__(self):
        self._load_config()

    def _load_config(self):
        # ── Frontend URL - used to build links that must point at the app
        # itself (e.g. where a Clerk invitation email sends the user after
        # they accept, since Clerk doesn't know this on its own) ────────────
        self.FRONTEND_URL = os.environ.get('FRONTEND_URL', 'http://localhost:3000').rstrip('/')

        # ── Email provider switch ────────────────────────────────────────────
        # Set to 'sendgrid', 'gmail', or 'outlook'
        self.EMAIL_PROVIDER = os.environ.get('EMAIL_PROVIDER', 'sendgrid').lower()

        # ── SendGrid (HTTPS port 443 – immune to firewall) ───────────────────
        self.SENDGRID_API_KEY    = os.environ.get('SENDGRID_API_KEY', '')
        self.SENDGRID_FROM_EMAIL = os.environ.get('SENDGRID_FROM_EMAIL', '')
        self.SENDGRID_FROM_NAME  = os.environ.get('SENDGRID_FROM_NAME', 'IT Security Team')

        # ── Gmail SMTP ───────────────────────────────────────────────────────
        # Requires a Gmail App Password (not your normal password):
        #   myaccount.google.com → Security → 2-Step Verification → App Passwords
        # SMTP_FROM_NAME can be ANY display name (e.g. "Microsoft Support")
        # NOTE: recipient sees the real @gmail.com address in email headers

        # ── Outlook / Hotmail SMTP ───────────────────────────────────────────
        # Use smtp-mail.outlook.com:587 with your Outlook.com credentials
        # Use smtp.office365.com:587 for work Office365 accounts

        # Shared SMTP settings (used for gmail / outlook providers)
        self.SMTP_HOST       = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
        self.SMTP_PORT       = int(os.environ.get('SMTP_PORT', '465'))
        self.SMTP_USERNAME   = os.environ.get('SMTP_USERNAME', '')
        self.SMTP_PASSWORD   = os.environ.get('SMTP_PASSWORD', '')
        self.SMTP_FROM_EMAIL = os.environ.get('SMTP_FROM_EMAIL', '')
        self.SMTP_FROM_NAME  = os.environ.get('SMTP_FROM_NAME', 'IT Security Team')
        # 465 = implicit SSL, 587 = STARTTLS
        self.SMTP_USE_SSL    = int(os.environ.get('SMTP_PORT', '465')) == 465

        # Bulk send tuning
        # PRE_SEND_VALIDATION: 'dns' (fast, default), 'smtp' (slow/deep), 'none'
        self.PRE_SEND_VALIDATION = os.environ.get('PRE_SEND_VALIDATION', 'dns').lower()
        # Gmail needs slower default pacing to avoid temporary throttling.
        default_send_delay = '1.2' if self.EMAIL_PROVIDER == 'gmail' else '0.05'
        default_fallback_delay = '2.0' if self.EMAIL_PROVIDER == 'gmail' else '0.25'
        # Delay between successful sends while reusing SMTP connection
        self.SEND_DELAY_SEC = float(os.environ.get('SEND_DELAY_SEC', default_send_delay))
        # Delay between fallback per-email sends when batch connection is unavailable
        self.SEND_FALLBACK_DELAY_SEC = float(os.environ.get('SEND_FALLBACK_DELAY_SEC', default_fallback_delay))
        # Retry count for transient SMTP/API failures
        self.SEND_RETRY_COUNT = int(os.environ.get('SEND_RETRY_COUNT', '3'))
        self.SEND_RETRY_BASE_SEC = float(os.environ.get('SEND_RETRY_BASE_SEC', '1.5'))

        # Public base URL of this app – used to build tracking pixel URLs
        self.PHISHING_BASE_URL = os.environ.get('PHISHING_BASE_URL', 'http://localhost:8000')
        # Optional GitHub Pages landing page URL
        self.PHISHING_GITHUB_PAGES_URL = os.environ.get('PHISHING_GITHUB_PAGES_URL', '')

        # Google Gemini AI (Service Account – Vertex AI)
        self.GOOGLE_SERVICE_ACCOUNT_JSON = os.environ.get('GOOGLE_SERVICE_ACCOUNT_JSON', '')
        self.GOOGLE_GENAI_MODEL          = os.environ.get('GOOGLE_GENAI_MODEL', 'gemini-2.5-flash-lite')
        self.GOOGLE_CLOUD_LOCATION       = os.environ.get('GOOGLE_CLOUD_LOCATION', 'us-central1')

        # Organisation name shown on the phishing landing page awareness banner
        self.ORG_NAME = os.environ.get('ORG_NAME', 'Provana')

        # ── Clerk authentication (admin dashboard login) ─────────────────────
        self.CLERK_PUBLISHABLE_KEY = os.environ.get('CLERK_PUBLISHABLE_KEY', '')
        self.CLERK_SECRET_KEY      = os.environ.get('CLERK_SECRET_KEY', '')
        # Flask secret key for session encryption
        self.SECRET_KEY        = os.environ.get('SECRET_KEY', os.urandom(32).hex())

    def get_phishing_config(self) -> dict:
        return {
            'base_url':             self.PHISHING_BASE_URL,
            'github_pages_url':     self.PHISHING_GITHUB_PAGES_URL,
            # SendGrid
            'sendgrid_from_email':  self.SENDGRID_FROM_EMAIL,
            'sendgrid_from_name':   self.SENDGRID_FROM_NAME,
            # Google Gemini AI
            'google_service_account_json': self.GOOGLE_SERVICE_ACCOUNT_JSON,
            'google_genai_model':           self.GOOGLE_GENAI_MODEL,
            'google_cloud_location':        self.GOOGLE_CLOUD_LOCATION,
        }


# Global config instance
config = Config()
