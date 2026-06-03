"""
User model — authentification pour les 3 rôles : hospital, insurer, admin

Statuts possibles :
  - pending  : inscription soumise, en attente de validation admin
  - active   : compte approuvé, connexion autorisée
  - rejected : demande rejetée par l'admin
"""
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from .db import db


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id            = db.Column(db.Integer, primary_key=True)
    email         = db.Column(db.String(150), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role          = db.Column(db.String(20), nullable=False)  # 'hospital', 'insurer', 'admin'

    # 'pending' | 'active' | 'rejected'
    # Les comptes admin créés par seed sont directement 'active'
    status        = db.Column(db.String(20), nullable=False, default='pending')

    # Rétrocompatibilité : is_active est désormais calculé depuis status
    # On le garde en base pour ne pas casser les migrations existantes,
    # mais la logique métier utilise status.
    is_active     = db.Column(db.Boolean, default=False, nullable=False)

    created_at    = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login    = db.Column(db.DateTime, nullable=True)

    # Message de rejet optionnel (affiché à l'utilisateur)
    rejection_note = db.Column(db.String(500), nullable=True)

    # Date d'approbation ou de rejet
    reviewed_at   = db.Column(db.DateTime, nullable=True)
    reviewed_by   = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    # FK vers l'entité liée (une seule des deux sera non-null selon le rôle)
    hospital_id   = db.Column(db.Integer, db.ForeignKey('hospitals.id'), nullable=True)
    insurer_id    = db.Column(db.Integer, db.ForeignKey('insurers.id'),  nullable=True)

    # Relations
    reviewer = db.relationship('User', foreign_keys=[reviewed_by], remote_side=[id])

    # ── Flask-Login : on utilise status pour déterminer si le compte est actif ──
    @property
    def is_active(self):
        """Flask-Login utilise cette propriété pour autoriser la connexion."""
        return self.status == 'active'

    @is_active.setter
    def is_active(self, value):
        """
        Setter de rétrocompatibilité.
        Permet au code existant (seed admin, toggle admin) de continuer
        à écrire `user.is_active = True/False` sans erreur.
        """
        if value:
            self.status = 'active'
        else:
            # Ne pas écraser 'rejected' si déjà rejeté
            if self.status not in ('rejected',):
                self.status = 'pending'

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @property
    def is_pending(self):
        return self.status == 'pending'

    @property
    def is_rejected(self):
        return self.status == 'rejected'

    def approve(self, admin_user):
        """Approuve le compte : status → active."""
        self.status      = 'active'
        self.reviewed_at = datetime.utcnow()
        self.reviewed_by = admin_user.id
        self.rejection_note = None

    def reject(self, admin_user, note: str = None):
        """Rejette le compte : status → rejected."""
        self.status         = 'rejected'
        self.reviewed_at    = datetime.utcnow()
        self.reviewed_by    = admin_user.id
        self.rejection_note = note

    def __repr__(self):
        return f'<User {self.email} [{self.role}] [{self.status}]>'