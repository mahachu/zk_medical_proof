"""
Auth Views — Gestion de l'authentification.

Connexion   : bloque si status != 'active', affiche message selon status
Inscription : crée le compte avec status='pending', attend validation admin
Déconnexion : fermeture de session
"""
from datetime import datetime
from flask import (Blueprint, render_template, request,
                   redirect, url_for, flash)
from flask_login import login_user, logout_user, login_required, current_user
from flask import session

from ..models.db import db
from ..models.user import User
from ..models.hospital import Hospital
from ..models.insurer import Insurer
from ..models.audit_log import AuditLog

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


# ── Helpers ──────────────────────────────────────────────────────────────────

def _log(action: str, role: str, desc: str, user_id=None):
    log = AuditLog(
        actor_user_id=user_id,
        actor_role=role,
        action=action,
        description=desc,
        ip_address=request.remote_addr,
    )
    db.session.add(log)
    db.session.commit()


def _redirect_by_role(role: str):
    routes = {
        'hospital': 'hospital.dashboard',
        'insurer':  'insurer.dashboard',
        'admin':    'admin.dashboard',
    }
    return redirect(url_for(routes.get(role, 'auth.login')))


# ── Routes ───────────────────────────────────────────────────────────────────

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """
    Connexion avec gestion des trois statuts :
      - active   → connexion autorisée
      - pending  → message "en attente de validation"
      - rejected → message "demande refusée" + note éventuelle
    """
    if current_user.is_authenticated:
        return _redirect_by_role(current_user.role)

    error        = None

    if request.method == 'POST':
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        role     = request.form.get('role', '')

        user = User.query.filter_by(email=email, role=role).first()

        if user and user.check_password(password):
            if user.status == 'active':
                user.last_login = datetime.utcnow()
                db.session.commit()
                login_user(user, remember=True)
                
                flash("✅ Connexion réussie.", "success")
                _log('login', role, f"Connexion réussie — rôle : {role}", user.id)
                return _redirect_by_role(role)

            elif user.status == 'pending':
                flash("⏳ Votre compte est en attente de validation par l'administrateur.", 'warning')
                _log('login_blocked_pending', role,
                    f"Tentative connexion — compte en attente : {email}")

            elif user.status == 'rejected':
                note = user.rejection_note or "Contactez l'administrateur pour plus d'informations."
                flash(f"❌ Demande d'inscription rejetée. {note}", 'danger')
                _log('login_blocked_rejected', role,
                    f"Tentative connexion — compte rejeté : {email}")
            
            elif user.status == 'suspended':
                flash(
                    "🚫 Votre compte a été suspendu. Veuillez contacter l'administrateur.",
                    'danger'
                )
                _log(
                    'login_blocked_suspended',
                    role,
                    f"Tentative connexion — compte suspendu : {email}"
                )
        else:
            error = "Email, mot de passe ou rôle incorrect."
            _log('login_failed', role or 'unknown',
                 f"Tentative de connexion échouée : {email}")

    return render_template('auth/login.html', error=error)



@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """
    Inscription avec status='pending'.
    Redirige vers une page de confirmation après soumission.
    L'admin devra approuver le compte depuis /admin/pending.
    """
    if current_user.is_authenticated:
        return _redirect_by_role(current_user.role)

    error = None

    if request.method == 'POST':
        email        = request.form.get('email', '').strip().lower()
        password     = request.form.get('password', '')
        confirm      = request.form.get('confirm_password', '')
        role         = request.form.get('role', '')
        entity_nom   = request.form.get('entity_nom', '').strip().upper()
        entity_ville = request.form.get('entity_ville', '').strip().upper()
        entity_pays  = request.form.get('entity_pays', 'Cameroun').strip().upper()

        # Validations
        if role not in ('hospital', 'insurer'):
            error = "Seuls les rôles hôpital et assureur peuvent s'inscrire."
        elif not email or not password:
            error = "Email et mot de passe obligatoires."
        elif password != confirm:
            error = "Les mots de passe ne correspondent pas."
        elif len(password) < 6:
            error = "Le mot de passe doit contenir au moins 6 caractères."
        elif User.query.filter_by(email=email).first():
            error = "Cet email est déjà utilisé."
        elif not entity_nom:
            error = "Le nom de l'entité est obligatoire."
        else:
            # Création du compte en statut 'pending'
            user = User(email=email, role=role, status='pending')
            user.set_password(password)

            if role == 'hospital':
                entity = Hospital(nom=entity_nom, ville=entity_ville, pays=entity_pays)
                db.session.add(entity)
                db.session.flush()
                user.hospital_id = entity.id
            else:
                entity = Insurer(nom=entity_nom, ville=entity_ville, pays=entity_pays)
                db.session.add(entity)
                db.session.flush()
                user.insurer_id = entity.id

            db.session.add(user)
            db.session.commit()

            _log('register_pending', role,
                 f"Inscription soumise — en attente admin : {email} / {entity_nom}",
                 user.id)

            # Redirige vers page de confirmation (pas vers login)
            return redirect(url_for('auth.register_pending',
                                    email=email, role=role,
                                    entity=entity_nom))

    return render_template('auth/register.html', error=error)


@auth_bp.route('/register/pending')
def register_pending():
    """
    Page affichée après inscription réussie.
    Informe l'utilisateur que sa demande est en attente de validation.
    """
    email  = request.args.get('email', '')
    role   = request.args.get('role', '')
    entity = request.args.get('entity', '')
    return render_template('auth/register_pending.html',
                           email=email, role=role, entity=entity)


@auth_bp.route('/logout')
@login_required
def logout():
    role = current_user.role
    _log('logout', role, f"Déconnexion — rôle : {role}", current_user.id)
    logout_user()
    flash('Déconnexion réussie.', 'info')
    return redirect(url_for('auth.login'))