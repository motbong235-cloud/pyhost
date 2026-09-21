PyHost — Deploy on Render (production)
======================================

1) Create Web Service from this folder
2) Add Persistent Disk: mount path /var/data
3) Set env vars (see render.yaml)

Required:
  SECRET_KEY          (auto or random)
  DATA_DIR=/var/data
  KHPAY_API_KEY=ak_...
  KHPAY_WEBHOOK_SECRET=long-random-string

Optional:
  FREE_TRIAL_SECONDS=900
  ALLOW_DEMO_UPGRADE=0     # MUST stay 0 in production
  SESSION_COOKIE_SECURE=1
  REQUIRE_WEBHOOK_SECRET=1

4) KHPAY Dashboard webhook:
   URL:    https://YOUR-APP.onrender.com/webhooks/khpay
   Secret: same as KHPAY_WEBHOOK_SECRET
   Header: X-Webhook-Secret: <secret>

Security built-in:
  - No plan activate without KHPAY server-side confirm
  - Demo upgrade disabled unless ALLOW_DEMO_UPGRADE=1
  - Webhook must re-verify via GET /qr/check
  - Rate limits (login/register/upgrade/status/webhook)
  - PBKDF2 passwords, secure session cookies
  - Security headers + basic CSP
  - Audit log: data/audit.jsonl
  - Path traversal protection on project files

Local test:
  export ALLOW_DEMO_UPGRADE=1   # only local
  export SESSION_COOKIE_SECURE=0
  pip install -r requirements.txt
  python app.py
