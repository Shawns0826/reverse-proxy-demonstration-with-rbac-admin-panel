"""add user auth_session_id for single active client JWT

Revision ID: f1a2b3c4d5e6
Revises: d1e2f3a4b5c6
Create Date: 2026-03-27

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = 'f1a2b3c4d5e6'
down_revision = 'd1e2f3a4b5c6'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    insp = inspect(conn)
    cols = {c['name'] for c in insp.get_columns('user')}
    if 'auth_session_id' in cols:
        return
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('auth_session_id', sa.String(length=36), nullable=True))


def downgrade():
    conn = op.get_bind()
    insp = inspect(conn)
    cols = {c['name'] for c in insp.get_columns('user')}
    if 'auth_session_id' not in cols:
        return
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('auth_session_id')
