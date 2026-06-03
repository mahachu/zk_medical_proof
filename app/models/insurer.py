"""
Insurer model — Vérifieur ZK
"""
from datetime import datetime
from .db import db


class Insurer(db.Model):
    __tablename__ = 'insurers'

    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(150), nullable=False)
    ville = db.Column(db.String(100), nullable=False)
    pays = db.Column(db.String(100), nullable=False, default='Cameroun')
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Relations
    users = db.relationship('User', backref='insurer', lazy='dynamic',
                            foreign_keys='User.insurer_id')
    verifications = db.relationship('Verification', backref='insurer', lazy='dynamic')

    def to_dict(self):
        return {
            'id': self.id,
            'nom': self.nom,
            'ville': self.ville,
            'pays': self.pays,
        }

    def __repr__(self):
        return f'<Insurer {self.nom}>'