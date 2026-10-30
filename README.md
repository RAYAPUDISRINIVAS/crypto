# Cryptography Key Management

Django application for managing encryption keys and encrypted data.

## Deploy on Render

The application uses a Render-managed PostgreSQL database. The Blueprint
creates the database, supplies its private connection URL to the web service,
and creates the application's tables before starting Gunicorn.

1. Push this repository to GitHub.
2. In the [Render Dashboard](https://dashboard.render.com/blueprints), select
   **New Blueprint Instance**, connect this repository, and apply `render.yaml`.
3. Review Render's displayed database plan and price before applying the
   Blueprint. The configured PostgreSQL plan is a paid persistent database.
4. Generate a Fernet master key locally:

   ```powershell
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```

   Set the resulting value as `KEYAPP_MASTER_KEY` in Render. Keep it stable and
   backed up; changing it prevents decrypting existing wrapped user keys.
5. Wait for the Render build and health check to complete. Render assigns the
   service its public `.onrender.com` address.

The Blueprint installs dependencies, collects static files, creates the
PostgreSQL schema, and runs Gunicorn. It generates `DJANGO_SECRET_KEY` and
provides `DATABASE_URL` from the managed database. Never commit database
credentials or encryption keys to this repository.

## Local setup

Install dependencies with `python -m pip install -r requirements.txt`, set
`DJANGO_SECRET_KEY`, `KEYAPP_MASTER_KEY`, and `DATABASE_URL` to a PostgreSQL
connection string, then run `python manage.py ensure_keyapp_schema` followed by
`python manage.py runserver`.
