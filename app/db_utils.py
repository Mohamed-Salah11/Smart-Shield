from contextlib import contextmanager
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
        conn.close()