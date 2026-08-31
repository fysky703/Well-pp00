# Modified files
Install dependencies with npm install at the project root. Enable Gmail API and register GMAIL_REDIRECT_URI. This implementation uses Gmail read-only OAuth for accounts that explicitly authorize the app. For production, encrypt refresh tokens at rest and use a strong OAUTH_STATE_SECRET.
