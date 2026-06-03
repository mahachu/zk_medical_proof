"""
Verification model — Résultat de vérification par l'assureur
"""
from datetime import datetime
from .db import db


class Verification(db.Model):
    __tablename__ = 'verifications'

    id = db.Column(db.Integer, primary_key=True)
    verification_uid = db.Column(db.String(64), unique=True, nullable=False, index=True)

    # Références
    proof_id = db.Column(db.Integer, db.ForeignKey('proofs.id'), nullable=False)
    insurer_id = db.Column(db.Integer, db.ForeignKey('insurers.id'), nullable=False)

    # Résultat global
    is_valid = db.Column(db.Boolean, nullable=False, default=False)
    predicate_satisfied = db.Column(db.Boolean, nullable=False, default=False)

    # Détails de vérification
    range_proof_valid = db.Column(db.Boolean, nullable=False, default=False)
    knowledge_proof_valid = db.Column(db.Boolean, nullable=False, default=False)
    error_message = db.Column(db.Text, nullable=True)

    # Métriques (visibles admin seulement)
    verification_time_ms = db.Column(db.Float, nullable=False, default=0.0)
    proof_size_bytes = db.Column(db.Integer, nullable=False, default=0)

    verified_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'verification_uid': self.verification_uid,
            'proof_id': self.proof_id,
            'insurer_id': self.insurer_id,
            'is_valid': self.is_valid,
            'predicate_satisfied': self.predicate_satisfied,
            'range_proof_valid': self.range_proof_valid,
            'knowledge_proof_valid': self.knowledge_proof_valid,
            'error_message': self.error_message,
            'verification_time_ms': round(self.verification_time_ms, 3),
            'proof_size_bytes': self.proof_size_bytes,
            'verified_at': self.verified_at.isoformat(),
        }

    def __repr__(self):
        status = 'VALID' if self.is_valid else 'INVALID'
        return f'<Verification {self.verification_uid} [{status}]>'