from contextlib import contextmanager

from flask import has_app_context

from app.database import get_db


@contextmanager
def db_cursor(commit=False):
    conn = get_db()
    cur = conn.cursor()
    try:
        yield conn, cur
        if commit:
            conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        # Inside a Flask request the connection is cached on `g` and closed by
        # the close_db() teardown handler — closing it here would discard the
        # cached connection mid-request and force later callers to reconnect.
        # Only close in non-request contexts (CLI, background threads) where
        # no teardown handler will run.
        if not has_app_context():
            conn.close()
