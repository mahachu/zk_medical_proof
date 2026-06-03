"""
AuditLog model — Toutes les actions de l'hôpital et de l'assureur
Visible uniquement par l'administrateur.
"""
from datetime import datetime
from .db import db


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    actor_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    actor_role = db.Column(db.String(20), nullable=False)  # hospital / insurer / admin
    action = db.Column(db.String(100), nullable=False)     # ex: 'generate_proof', 'verify_proof'
    description = db.Column(db.Text, nullable=True)
    resource_type = db.Column(db.String(50), nullable=True)  # 'proof', 'patient', etc.
    resource_id = db.Column(db.String(64), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Relations
    actor = db.relationship('User', foreign_keys=[actor_user_id])

    def to_dict(self):
        return {
            'id': self.id,
            'actor_role': self.actor_role,
            'action': self.action,
            'description': self.description,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'created_at': self.created_at.isoformat(),
        }

    def __repr__(self):
        return f'<AuditLog {self.action} by {self.actor_role}>'