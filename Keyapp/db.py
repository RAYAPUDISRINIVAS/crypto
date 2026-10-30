import os

import pymysql
from django.core.exceptions import ImproperlyConfigured


def get_connection():
    """Create and return a connection to the configured MySQL database."""
    setting_names = {
        "host": "KEYAPP_DB_HOST",
        "user": "KEYAPP_DB_USER",
        "password": "KEYAPP_DB_PASSWORD",
        "database": "KEYAPP_DB_NAME",
    }
    settings = {key: os.environ.get(name) for key, name in setting_names.items()}
    missing = [
        setting_names[key]
        for key, value in settings.items()
        if not value
    ]
    if missing:
        raise ImproperlyConfigured(
            "Set the following environment variables: " + ", ".join(missing)
        )

    try:
        port = int(os.environ.get("KEYAPP_DB_PORT", "3306"))
    except ValueError as exc:
        raise ImproperlyConfigured("KEYAPP_DB_PORT must be an integer.") from exc

    return pymysql.connect(
        **settings,
        port=port,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
        connect_timeout=10,
    )
