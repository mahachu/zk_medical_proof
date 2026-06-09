from datetime import datetime
from .db import db

class Subscription(db.Model):
    __tablename__ = 'subscriptions'

    id = db.Column(db.Integer, primary_key=True)
    insurer_id = db.Column(db.Integer, db.ForeignKey('insurers.id'), nullable=False)
    numero_contrat = db.Column(db.String(50), nullable=True)
    nom = db.Column(db.String(100), nullable=False)
    prenom = db.Column(db.String(100), nullable=False)  
    numero_cni = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    insurer = db.relationship('Insurer', backref='assures')

    def full_name(self):
        return f"{self.nom} {self.prenom}"

    def __repr__(self):
        return f'<Subscription {self.nom} {self.prenom} — assureur={self.insurer_id}>'