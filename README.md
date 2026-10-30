# Cryptography Key Management

Django application for managing encryption keys and encrypted data.

## Deploy on Render

This application uses MySQL-specific SQL and a MySQL schema. Render's managed
database is PostgreSQL, so provide a MySQL database hosted by a service that
allows connections from Render.

1. Create a MySQL database and run the schema in [`db.txt`](db.txt).
2. Push this repository to GitHub.
3. In the [Render Dashboard](https://dashboard.render.com/blueprints), select
   **New Blueprint Instance**, connect this repository, and apply `render.yaml`.
4. Enter the MySQL host, port, user, password, and database name when prompted.
   Keep the database credentials private and restrict database network access
   according to your provider's instructions.
5. Generate a Fernet master key locally:

   ```powershell
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```

   Set the resulting value as `KEYAPP_MASTER_KEY` in Render. Keep it stable and
   backed up; changing it prevents decrypting existing wrapped user keys.
6. Wait for the Render build and health check to complete. Render assigns the
   service its public `.onrender.com` address.

The Blueprint installs dependencies, collects static files, and runs Gunicorn.
It generates `DJANGO_SECRET_KEY`; database credentials and the Fernet master
key are entered privately in Render rather than stored in this repository.

## Local setup

Install dependencies with `python -m pip install -r requirements.txt`, set
`DJANGO_SECRET_KEY`, `KEYAPP_MASTER_KEY`, and `KEYAPP_DB_HOST`,
`KEYAPP_DB_PORT`, `KEYAPP_DB_USER`, `KEYAPP_DB_PASSWORD`, and `KEYAPP_DB_NAME`,
then run `python manage.py runserver`.
