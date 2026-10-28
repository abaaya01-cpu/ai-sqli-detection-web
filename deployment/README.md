# Free demonstration deployment

This Render Blueprint selects **plan: free**, one service and **no paid disk or
database**. It runs the existing Flask application and word LSTM + rules detector
without changing detection thresholds, preprocessing or website pages. The clean
package excludes local databases, accounts, secrets, datasets and experiment records.

## Limits

- Free Render services sleep after 15 idle minutes. SQLite data is lost when the
  service sleeps, restarts or redeploys. Registered users, contact messages and
  security events then start empty again. This is a demonstration, not durable
  production hosting.
- The sole administrator is recreated from private hosting environment values
  after a fresh start. Existing administrator credentials are never reset while
  the database still exists.
- Free compute has 512 MB RAM. The current app, model and one inference measured
  about 408 MiB working set on Windows. Linux hosting memory is not yet measured;
  confirm the model fits from actual deployment logs. No paid upgrade is automatic.
- For strictly free operation, use a free Hobby workspace without a payment
  method. Accept suspension when monthly allowances are exhausted. Do not add a
  payment method or upgrade resources.

## Publish

1. Put this clean package in a private GitHub repository, with app.py and
   render.yaml at its root. .gitattributes preserves the tested file bytes.
2. In Render, create a Blueprint from that repository. Confirm it lists exactly
   one **Free** web service and no disks or databases before creating it.
3. Python 3.12 is selected by .python-version. Build with:

   pip install -r requirements-deploy.txt

   Start with:

   gunicorn --config deployment/gunicorn.conf.py deployment.wsgi:app

4. Render generates private SECRET_KEY and ADMIN_PASSWORD values. Keep both
   stable. The login email is admin@gmail.com. Read the generated password in
   the service environment settings; never commit it or place it in build
   commands or URLs. The local project's old password is not copied.
5. Open the issued HTTPS URL and check public pages, registration, login,
   contact, administrator access and AI status (active mode hybrid).
   Verify cold starts and memory limits from real hosting logs.

Free Render services do not provide an interactive shell. The deployment worker
initializes its database and sole administrator on startup. Gunicorn 26.2.0 uses
one synchronous worker and one request thread; TensorFlow CPU thread pools are limited to one each.
Secure session cookies and a stable random session key are required. Automatic
deployment is disabled. The health check is /login; model startup and database
initialization must finish before the page is served.

This setup adds no rate limiting, email verification, production monitoring or
independent security audit. Do not use this free demo to retain important data.

## Sources

- https://render.com/docs/free
- https://render.com/docs/deploy-flask
- https://render.com/docs/blueprint-spec
- https://render.com/docs/python-version
- https://pypi.org/project/gunicorn/
