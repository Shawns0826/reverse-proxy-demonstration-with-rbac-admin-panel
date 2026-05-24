"""Rename godadmin role to rootadmin

Revision ID: b8c4e2f1a903
Revises: f1a2b3c4d5e6
Create Date: 2026-05-23

"""
from alembic import op


revision = "b8c4e2f1a903"
down_revision = "f1a2b3c4d5e6"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("UPDATE \"user\" SET role = 'rootadmin' WHERE role = 'godadmin'")


def downgrade():
    op.execute("UPDATE \"user\" SET role = 'godadmin' WHERE role = 'rootadmin'")
