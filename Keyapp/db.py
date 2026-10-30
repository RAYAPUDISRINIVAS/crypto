import os

import pymysql
from django.core.exceptions import ImproperlyConfigured


def get_connection():
    """Create and return a connection to the MySQL database."""
    db_password = os.environ.get("KEYAPP_DB_PASSWORD")
    if db_password is None:
        raise ImproperlyConfigured(
            "KEYAPP_DB_PASSWORD must be set in the environment."
        )

    return pymysql.connect(
        host="127.0.0.1",
        port=3306,
        user="root",
        password=db_password,
        database="key_db",
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
    )
