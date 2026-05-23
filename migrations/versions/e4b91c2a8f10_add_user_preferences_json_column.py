"""add user preferences JSON column

Revision ID: e4b91c2a8f10
Revises: fc328d5d0fee
Create Date: 2026-03-24

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = 'e4b91c2a8f10'
down_revision = 'fc328d5d0fee'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    insp = inspect(conn)
    cols = {c['name'] for c in insp.get_columns('user')}
    if 'preferences' in cols:
        return
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('preferences', sa.JSON(), nullable=True))


def downgrade():
    conn = op.get_bind()
    insp = inspect(conn)
    cols = {c['name'] for c in insp.get_columns('user')}
    if 'preferences' not in cols:
        return
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('preferences')
