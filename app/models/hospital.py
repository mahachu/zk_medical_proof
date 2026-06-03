"""
Hospital model — Prouveur ZK
"""
from datetime import datetime
from .db import db


class Hospital(db.Model):
    __tablename__ = 'hospitals'

    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(150), nullable=False)
    ville = db.Column(db.String(100), nullable=False)
    pays = db.Column(db.String(100), nullable=False, default='Cameroun')
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Relations
    users = db.relationship('User', backref='hospital', lazy='dynamic',
                            foreign_keys='User.hospital_id')
    patients = db.relationship('Patient', backref='hospital', lazy='dynamic')
    proofs = db.relationship('Proof', backref='hospital', lazy='dynamic')

    def to_dict(self):
        return {
            'id': self.id,
            'nom': self.nom,
            'ville': self.ville,
            'pays': self.pays,
        }

    def __repr__(self):
        return f'<Hospital {self.nom}>'