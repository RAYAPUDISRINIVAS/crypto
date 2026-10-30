import os

import psycopg
from django.core.exceptions import ImproperlyConfigured
from psycopg.rows import dict_row


def get_connection():
    """Create and return a connection to the configured PostgreSQL database."""
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise ImproperlyConfigured("DATABASE_URL must be set in the environment.")

    return psycopg.connect(
        database_url,
        row_factory=dict_row,
        autocommit=True,
        connect_timeout=10,
    )
