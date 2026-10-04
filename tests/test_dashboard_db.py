"""Persistence contracts for hosted tenant data."""

import unittest
from datetime import timezone
from uuid import UUID, uuid4

from sqlalchemy import create_engine, event, inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from dashboard.db.models import Audit, Base, Finding, Organization, Repository, User
from dashboard.db.migrate import install_rls
from dashboard.db.session import tenant_scope


class SchemaTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite+pysqlite:///:memory:")

        @event.listens_for(self.engine, "connect")
        def foreign_keys(connection, _record):
            connection.execute("PRAGMA foreign_keys=ON")

        Base.metadata.create_all(self.engine)

    def tearDown(self):
        self.engine.dispose()

    def test_hosted_tables_with_uuid_keys_and_tenant_foreign_keys(self):
        tables = set(inspect(self.engine).get_table_names())
        self.assertEqual(tables, {"users", "organizations", "org_members", "api_keys", "repositories", "audits", "findings", "stripe_events"})
        columns = lambda table: {column["name"] for column in inspect(self.engine).get_columns(table)}
        self.assertIn("is_active", columns("repositories"))
        self.assertTrue({"total_findings", "high_count", "medium_count", "low_count", "diff_size"} <= columns("audits"))
        self.assertIn("is_fixed", columns("findings"))
        self.assertTrue({"stripe_subscription_id", "billing_status", "billing_event_created", "seat_count"} <= columns("organizations"))
        with Session(self.engine) as session, session.begin():
            user = User(github_id=100, login="alice")
            session.add(user)
            session.flush()
            org = Organization(name="acme", owner_id=user.id)
            session.add(org)
            session.flush()
            repo = Repository(org_id=org.id, github_repo_full_name="acme/app")
            session.add(repo)
            session.flush()
            audit = Audit(org_id=org.id, repo_id=repo.id, status="QUEUED")
            session.add(audit)
            session.flush()
            finding = Finding(org_id=org.id, audit_id=audit.id, severity="HIGH", category="secret", description="exposed", line_reference="Line 1", remediation="rotate")
            session.add(finding)
            session.flush()
            self.assertTrue(all(isinstance(item.id, UUID) for item in (user, org, repo, audit, finding)))
            self.assertIsNotNone(finding.created_at)
            self.assertEqual(finding.created_at.tzinfo, timezone.utc)

    def test_duplicate_repository_name_within_org_is_rejected(self):
        with Session(self.engine) as session:
            user = User(github_id=100, login="alice")
            session.add(user)
            session.flush()
            org = Organization(name="acme", owner_id=user.id)
            session.add(org)
            session.flush()
            session.add(Repository(org_id=org.id, github_repo_full_name="acme/app"))
            session.commit()
            session.add(Repository(org_id=org.id, github_repo_full_name="acme/app"))
            with self.assertRaises(IntegrityError):
                session.commit()

    def test_cross_org_repository_link_is_rejected(self):
        with Session(self.engine) as session:
            user = User(github_id=100, login="alice")
            session.add(user)
            session.flush()
            first = Organization(name="one", owner_id=user.id)
            second = Organization(name="two", owner_id=user.id)
            session.add_all([first, second])
            session.flush()
            repo = Repository(org_id=first.id, github_repo_full_name="one/app")
            session.add(repo)
            session.flush()
            session.add(Audit(org_id=second.id, repo_id=repo.id, status="QUEUED"))
            with self.assertRaises(IntegrityError):
                session.commit()


class TenantPolicyTests(unittest.TestCase):
    def test_scope_uses_transaction_local_database_setting(self):
        class RecordingSession:
            def __init__(self):
                self.sql = None
                self.params = None

            def in_transaction(self):
                return True

            def execute(self, sql, params):
                self.sql = str(sql)
                self.params = params

        session = RecordingSession()
        org_id = uuid4()
        tenant_scope(session, org_id)
        self.assertIn("set_config", session.sql)
        self.assertIn("true", session.sql.lower())
        self.assertEqual(session.params["org_id"], str(org_id))

    def test_scope_refuses_no_transaction(self):
        class ClosedSession:
            def in_transaction(self):
                return False

        with self.assertRaises(RuntimeError):
            tenant_scope(ClosedSession(), uuid4())

    def test_scope_can_run_with_sqlite_session_for_local_tests(self):
        engine = create_engine("sqlite+pysqlite:///:memory:")
        try:
            with Session(engine) as session, session.begin():
                tenant_scope(session, uuid4())
        finally:
            engine.dispose()

    def test_rls_installer_forces_tenant_policies_on_all_three_tables(self):
        class RecordingConnection:
            def __init__(self):
                self.sql = []

            def execute(self, statement, parameters=None):
                self.sql.append(str(statement))

        connection = RecordingConnection()
        install_rls(connection)
        sql = "\n".join(connection.sql).lower()
        for table in ("repositories", "audits", "findings"):
            self.assertIn(f"alter table {table} enable row level security", sql)
            self.assertIn(f"alter table {table} force row level security", sql)
            self.assertIn(f"create policy", sql)
        self.assertIn("current_setting('app.current_org_id', true)", sql)
        self.assertIn("with check", sql)


if __name__ == "__main__":
    unittest.main()
