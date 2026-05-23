"""drop user preferences column (revert client-overlay experiment)

Revision ID: d1e2f3a4b5c6
Revises: e4b91c2a8f10
Create Date: 2026-03-24

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = 'd1e2f3a4b5c6'
down_revision = 'e4b91c2a8f10'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    insp = inspect(conn)
    cols = {c['name'] for c in insp.get_columns('user')}
    if 'preferences' not in cols:
        return
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('preferences')


def downgrade():
    conn = op.get_bind()
    insp = inspect(conn)
    cols = {c['name'] for c in insp.get_columns('user')}
    if 'preferences' in cols:
        return
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('preferences', sa.JSON(), nullable=True))
