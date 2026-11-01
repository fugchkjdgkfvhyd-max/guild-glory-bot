# ROCKS GUILD GLORY BOT

A GitHub-ready Node.js/Express starter with:
- User registration/login and profile
- Separate owner-only admin route (`/admin`)
- Credit quantity and server-calculated totals
- UPI QR generation and manual payment submission
- Admin payment review with Accept/Reject
- Credits granted exactly once after acceptance
- Telegram notifications and one-time account linking
- Safe read-only external API proxy for the documented GET paths
- SQLite persistence and uploaded payment receipts

## Important deployment notes

**GitHub stores your code; it does not run this backend.** Deploy this project to a Node.js host (for example Render) and connect the GitHub repository. Persistent disk is required because this starter uses SQLite and local receipt uploads. For production scale, migrate SQLite and local uploads to managed PostgreSQL and private object storage.

## Run locally

1. Install Node.js 20 or newer.
2. Copy `.env.example` to `.env`.
3. Set a long random `SESSION_SECRET`, strong admin credentials, and UPI details.
4. `npm install`
5. `npm start`
6. Open `http://localhost:3000`

Never commit `.env`, API keys, bot tokens, payment credentials, database files, or uploaded receipts to GitHub.

## Admin

Open `/admin`. Admin credentials are read from `ADMIN_EMAIL`, `ADMIN_PASSWORD`, and `ADMIN_PIN`. Only this configured owner account can enter the admin area. Change all example values before deployment.

## Manual payment flow

User chooses credits -> server calculates amount -> QR is generated from configured UPI ID -> user uploads receipt and UTR -> payment becomes PENDING -> owner checks their actual receiving account -> owner accepts or rejects. Credits are added only once after acceptance.

A QR code or uploaded screenshot is not proof of payment. Verify the payment independently in the receiving account. Payment features should be operated by an eligible account holder with appropriate adult supervision.

## Telegram

Set `TELEGRAM_BOT_TOKEN`, `TELEGRAM_WEBHOOK_SECRET`, and `TELEGRAM_ADMIN_CHAT_ID` in the hosting provider's secret/environment settings. Configure Telegram webhook to:

`https://YOUR-DOMAIN/api/telegram/webhook`

Use Telegram's official `setWebhook` method and set `secret_token` to the same `TELEGRAM_WEBHOOK_SECRET`. Users can request a one-time link code from their profile, then send `/link CODE` to the bot. Bot messages are sent only to linked Telegram accounts.

## External API

The API integration is deliberately limited to server-side GET requests to the previously listed paths:
- `/api/auth/me`
- `/api/pricing`
- `/api/client/my-groups`
- `/api/client/group-history`
- `/api/client/activity-log`
- `/api/client/notifications`

The exact authentication header and response schemas must be confirmed from the provider's complete official documentation. The server currently uses `Authorization: Bearer ...` as shown in the supplied material. No undocumented POST/game-action/Glory-boosting operations are implemented. Guild UID lookup is not guessed because a verified read-only UID endpoint/schema was not supplied.

## Production hardening checklist

- Use HTTPS.
- Set secure cookies and a strong session secret.
- Use a persistent disk or migrate to managed database/object storage.
- Add a real transactional email provider for password reset (not included in this starter).
- Add CSRF protection and stronger account verification before public launch.
- Restrict admin credentials and rotate secrets.
- Review local legal/payment requirements with an adult account holder.
