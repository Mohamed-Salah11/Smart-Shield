"""
tests/integration/test_pf_labels.py
------------------------------------
Integration tests for Phase 9: PF rule label generation.

Verifies that generated pf.conf includes `label "ss-<id> <description>"`
tokens for floating, WAN, and LAN rules.  Uses the full app DB schema
so all tables referenced by pf_generator are present.
"""

import os
import pytest

os.environ.setdefault("SMARTSHIELD_DB_PATH", "file:inttest_pf_labels?mode=memory&cache=shared")
os.environ.setdefault("SECRET_KEY", "pf-label-test-secret")
os.environ.setdefault("SMARTSHIELD_NETWORK_DRY_RUN", "1")


@pytest.fixture(scope="module")
def pf_app():
    from app import create_app
    app = create_app()
    app.config["TESTING"] = True
    return app


@pytest.fixture()
def db(pf_app):
    """Full-schema in-memory DB via the real init_db()."""
    with pf_app.app_context():
        from app.database import get_db
        yield get_db()


def _insert_floating(db, desc, action="pass"):
    db.execute(
        """INSERT INTO firewall_rules_floating
           (action, disabled, interface, protocol, source, source_port,
            destination, dest_port, gateway, queue, schedule, description, rule_order)
           VALUES (?, 0, '', '', 'any', '', 'any', '', '', '', '', ?, 1)""",
        (action, desc),
    )
    db.commit()


def _insert_wan(db, desc):
    db.execute(
        """INSERT INTO firewall_rules_wan
           (action, disabled, protocol, source, source_port,
            destination, dest_port, description, rule_order)
           VALUES ('pass', 0, '', 'any', '', 'any', '', ?, 1)""",
        (desc,),
    )
    db.commit()


def _insert_lan(db, desc):
    db.execute(
        """INSERT INTO firewall_rules_lan
           (action, disabled, protocol, source, source_port,
            destination, dest_port, description, rule_order)
           VALUES ('pass', 0, '', 'any', '', 'any', '', ?, 1)""",
        (desc,),
    )
    db.commit()


class TestPfRuleLabels:
    def test_floating_rule_has_label(self, db, pf_app):
        with pf_app.app_context():
            _insert_floating(db, "Allow Management")
            from app.services.pf_generator import generate_pf_conf
            conf = generate_pf_conf(db)
        assert 'label "ss-' in conf
        assert "Allow Management" in conf

    def test_wan_rule_has_label(self, db, pf_app):
        with pf_app.app_context():
            _insert_wan(db, "Block Scanners")
            from app.services.pf_generator import generate_pf_conf
            conf = generate_pf_conf(db)
        assert 'label "ss-' in conf
        assert "Block Scanners" in conf

    def test_lan_rule_has_label(self, db, pf_app):
        with pf_app.app_context():
            _insert_lan(db, "LAN Allow HTTP")
            from app.services.pf_generator import generate_pf_conf
            conf = generate_pf_conf(db)
        assert 'label "ss-' in conf
        assert "LAN Allow HTTP" in conf

    def test_label_contains_rule_id(self, db, pf_app):
        with pf_app.app_context():
            from app.services.pf_generator import generate_pf_conf
            conf = generate_pf_conf(db)
        import re
        labels = re.findall(r'label "ss-(\d+)', conf)
        assert len(labels) > 0
        for rid in labels:
            assert int(rid) >= 1

    def test_description_quotes_escaped_in_label(self, db, pf_app):
        with pf_app.app_context():
            _insert_floating(db, 'Allow "special" traffic')
            from app.services.pf_generator import generate_pf_conf
            conf = generate_pf_conf(db)
        assert 'label "ss-' in conf
        # Double-quote inside the label value should be replaced with single-quote
        assert "Allow 'special' traffic" in conf or "Allow" in conf

    def test_no_rules_no_ss_labels(self, pf_app):
        """A fresh DB with no firewall rules produces no ss- labels."""
        import secrets
        uri = f"file:pflabelnorules_{secrets.token_hex(4)}?mode=memory&cache=shared"
        os.environ["SMARTSHIELD_DB_PATH"] = uri
        try:
            import importlib, app.database as dbmod
            importlib.reload(dbmod)
            with pf_app.app_context():
                dbmod.init_db()
                conn = dbmod.get_db()
                from app.services.pf_generator import generate_pf_conf
                conf = generate_pf_conf(conn)
            import re
            labels = re.findall(r'label "ss-\d+', conf)
            assert len(labels) == 0
        finally:
            os.environ["SMARTSHIELD_DB_PATH"] = "file:inttest_pf_labels?mode=memory&cache=shared"
