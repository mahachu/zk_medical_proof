"""
Patient model — données médicales (côté hôpital)
"""
from datetime import datetime
from .db import db


class Patient(db.Model):
    __tablename__ = 'patients'

    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(100), nullable=False)
    prenom = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    # Température stockée en string pour conserver la précision décimale exacte
    temperature = db.Column(db.String(20), nullable=True)  # ex: "37.25", "38.1"
    hospital_id = db.Column(db.Integer, db.ForeignKey('hospitals.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)

    # Relations
    proofs = db.relationship('Proof', backref='patient', lazy='dynamic')

    @property
    def temperature_float(self):
        """Retourne la température en float avec précision maximale."""
        if self.temperature is None:
            return None
        return float(self.temperature)

    def to_dict(self):
        return {
            'id': self.id,
            'nom': self.nom,
            'prenom': self.prenom,
            'age': self.age,
            'temperature': self.temperature,
            'hospital_id': self.hospital_id,
            'created_at': self.created_at.isoformat(),
        }

    def full_name(self):
        return f"{self.nom} {self.prenom}"

    def __repr__(self):
        return f'<Patient {self.prenom} {self.nom}>'