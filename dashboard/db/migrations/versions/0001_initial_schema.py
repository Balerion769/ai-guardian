"""Create the initial hosted schema with immutable table definitions."""

import sqlalchemy as sa
from alembic import op

revision: str = "0001_initial_schema"
down_revision: str | None = None
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Create the tenant schema and enforce PostgreSQL organization policies."""
    op.create_table('users',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('github_id', sa.BigInteger(), nullable=False),
    sa.Column('login', sa.String(length=255), nullable=False),
    sa.Column('email', sa.String(length=320), nullable=True),
    sa.Column('name', sa.String(length=255), nullable=True),
    sa.Column('avatar_url', sa.String(length=2048), nullable=True),
    sa.Column('github_token_ciphertext', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('github_id')
    )
    op.create_table('organizations',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('github_org_name', sa.String(length=255), nullable=True),
    sa.Column('github_installation_id', sa.BigInteger(), nullable=True),
    sa.Column('github_app_installed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('owner_id', sa.Uuid(), nullable=False),
    sa.Column('plan', sa.String(length=40), nullable=False),
    sa.Column('stripe_customer_id', sa.String(length=255), nullable=True),
    sa.Column('stripe_subscription_id', sa.String(length=255), nullable=True),
    sa.Column('billing_status', sa.String(length=24), server_default='active', nullable=False),
    sa.Column('billing_event_created', sa.BigInteger(), server_default='0', nullable=False),
    sa.Column('seat_count', sa.Integer(), server_default='1', nullable=False),
    sa.Column('daily_limit', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("billing_status IN ('active', 'past_due')", name='ck_organizations_billing_status'),
    sa.CheckConstraint("plan IN ('free', 'pro', 'team')", name='ck_organizations_plan'),
    sa.CheckConstraint('daily_limit > 0', name='ck_organizations_daily_limit'),
    sa.CheckConstraint('seat_count > 0', name='ck_organizations_seat_count'),
    sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('github_installation_id'),
    sa.UniqueConstraint('github_org_name'),
    sa.UniqueConstraint('stripe_customer_id'),
    sa.UniqueConstraint('stripe_subscription_id')
    )
    op.create_table('api_keys',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('org_id', sa.Uuid(), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('key_prefix', sa.String(length=80), nullable=False),
    sa.Column('key_last4', sa.String(length=4), nullable=False),
    sa.Column('salt', sa.String(length=128), nullable=False),
    sa.Column('key_hash', sa.String(length=128), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
    sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('key_prefix')
    )
    op.create_index('ix_api_keys_org_id', 'api_keys', ['org_id'], unique=False)
    op.create_table('org_members',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('org_id', sa.Uuid(), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('role', sa.String(length=16), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("role IN ('owner', 'admin', 'member')", name='ck_org_members_role'),
    sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('org_id', 'user_id', name='uq_org_members_org_user')
    )
    op.create_index('ix_org_members_user_id', 'org_members', ['user_id'], unique=False)
    op.create_table('repositories',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('org_id', sa.Uuid(), nullable=False),
    sa.Column('github_repo_full_name', sa.String(length=512), nullable=False),
    sa.Column('default_branch', sa.String(length=255), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('last_audit_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('org_id', 'github_repo_full_name', name='uq_repositories_org_name'),
    sa.UniqueConstraint('org_id', 'id', name='uq_repositories_org_id_id')
    )
    op.create_index('ix_repositories_org_id', 'repositories', ['org_id'], unique=False)
    op.create_table('stripe_events',
    sa.Column('id', sa.String(length=255), nullable=False),
    sa.Column('event_type', sa.String(length=100), nullable=False),
    sa.Column('org_id', sa.Uuid(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('audits',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('org_id', sa.Uuid(), nullable=False),
    sa.Column('repo_id', sa.Uuid(), nullable=True),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('risk_score', sa.Integer(), nullable=True),
    sa.Column('summary', sa.Text(), nullable=True),
    sa.Column('total_findings', sa.Integer(), nullable=False),
    sa.Column('high_count', sa.Integer(), nullable=False),
    sa.Column('medium_count', sa.Integer(), nullable=False),
    sa.Column('low_count', sa.Integer(), nullable=False),
    sa.Column('diff_size', sa.Integer(), nullable=False),
    sa.Column('static_count', sa.Integer(), nullable=False),
    sa.Column('ai_count', sa.Integer(), nullable=False),
    sa.Column('latency_ms', sa.Float(), nullable=True),
    sa.Column('model_used', sa.String(length=255), nullable=True),
    sa.Column('pr_number', sa.Integer(), nullable=True),
    sa.Column('commit_sha', sa.String(length=64), nullable=True),
    sa.Column('branch', sa.String(length=255), nullable=True),
    sa.Column('triggered_by', sa.Uuid(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint("status IN ('QUEUED', 'RUNNING', 'PASSED', 'FAILED', 'ERROR')", name='ck_audits_status'),
    sa.CheckConstraint('risk_score IS NULL OR risk_score BETWEEN 0 AND 100', name='ck_audits_risk_score'),
    sa.ForeignKeyConstraint(['org_id', 'repo_id'], ['repositories.org_id', 'repositories.id'], name='fk_audits_tenant_repository'),
    sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
    sa.ForeignKeyConstraint(['triggered_by'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('org_id', 'id', name='uq_audits_org_id_id')
    )
    op.create_index('ix_audits_org_id_created_at', 'audits', ['org_id', 'created_at'], unique=False)
    op.create_index('ix_audits_repo_id', 'audits', ['repo_id'], unique=False)
    op.create_table('findings',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('org_id', sa.Uuid(), nullable=False),
    sa.Column('audit_id', sa.Uuid(), nullable=False),
    sa.Column('severity', sa.String(length=8), nullable=False),
    sa.Column('category', sa.String(length=255), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('file_path', sa.String(length=1024), nullable=True),
    sa.Column('line_number', sa.Integer(), nullable=True),
    sa.Column('line_reference', sa.String(length=512), nullable=False),
    sa.Column('remediation', sa.Text(), nullable=False),
    sa.Column('confidence', sa.Float(), nullable=False),
    sa.Column('tainted', sa.Boolean(), nullable=False),
    sa.Column('is_fixed', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('fixed_at', sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint("severity IN ('HIGH', 'MEDIUM', 'LOW')", name='ck_findings_severity'),
    sa.CheckConstraint('confidence BETWEEN 0 AND 1', name='ck_findings_confidence'),
    sa.ForeignKeyConstraint(['org_id', 'audit_id'], ['audits.org_id', 'audits.id'], name='fk_findings_tenant_audit'),
    sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_findings_audit_id', 'findings', ['audit_id'], unique=False)
    op.create_index('ix_findings_org_id_created_at', 'findings', ['org_id', 'created_at'], unique=False)
    if op.get_bind().dialect.name == "postgresql":
        predicate = "org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid"
        for table in ("repositories", "audits", "findings"):
            op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
            op.execute(f"CREATE POLICY {table}_tenant ON {table} FOR ALL USING ({predicate}) WITH CHECK ({predicate})")


def downgrade() -> None:
    """Remove the initial tables in reverse foreign-key dependency order."""
    op.drop_index('ix_findings_org_id_created_at', table_name='findings')
    op.drop_index('ix_findings_audit_id', table_name='findings')
    op.drop_table('findings')
    op.drop_index('ix_audits_repo_id', table_name='audits')
    op.drop_index('ix_audits_org_id_created_at', table_name='audits')
    op.drop_table('audits')
    op.drop_table('stripe_events')
    op.drop_index('ix_repositories_org_id', table_name='repositories')
    op.drop_table('repositories')
    op.drop_index('ix_org_members_user_id', table_name='org_members')
    op.drop_table('org_members')
    op.drop_index('ix_api_keys_org_id', table_name='api_keys')
    op.drop_table('api_keys')
    op.drop_table('organizations')
    op.drop_table('users')
