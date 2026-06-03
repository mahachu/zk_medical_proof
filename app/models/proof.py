"""
Proof model — Preuve ZK générée par l'hôpital
"""
from datetime import datetime
import json
from .db import db


class Proof(db.Model):
    __tablename__ = 'proofs'

    id = db.Column(db.Integer, primary_key=True)
    proof_uid = db.Column(db.String(64), unique=True, nullable=False, index=True)

    # Références
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=False)
    hospital_id = db.Column(db.Integer, db.ForeignKey('hospitals.id'), nullable=False)

    # Assureur destinataire (choix explicite de l'hôpital)
    target_insurer_id = db.Column(db.Integer, db.ForeignKey('insurers.id'), nullable=True)

    # Prédicat
    predicate = db.Column(db.String(100), nullable=False, default='temperature < 38°C')
    threshold = db.Column(db.String(20), nullable=False, default='38.0')

    # Composantes cryptographiques
    commitment_w = db.Column(db.Text, nullable=False)
    proof_json = db.Column(db.Text, nullable=False)
    proof_size_bytes = db.Column(db.Integer, nullable=False, default=0)
    generation_time_ms = db.Column(db.Float, nullable=False, default=0.0)

    is_downloaded = db.Column(db.Boolean, default=False)
    generated_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Relations
    verifications = db.relationship('Verification', backref='proof', lazy='dynamic')
    target_insurer = db.relationship('Insurer', foreign_keys=[target_insurer_id])
    

    def get_proof_data(self):
        return json.loads(self.proof_json)

    def to_summary_dict(self):
        return {
            'id': self.id,
            'proof_uid': self.proof_uid,
            'patient_id': self.patient_id,
            'hospital_id': self.hospital_id,
            'target_insurer_id': self.target_insurer_id,
            'predicate': self.predicate,
            'threshold': self.threshold,
            'proof_size_bytes': self.proof_size_bytes,
            'generation_time_ms': round(self.generation_time_ms, 3),
            'generated_at': self.generated_at.isoformat(),
        }

    def __repr__(self):
        return f'<Proof {self.proof_uid}>'