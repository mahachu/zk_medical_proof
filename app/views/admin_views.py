"""
Admin Views — Vue globale du système + gestion des demandes d'inscription.

Nouvelles routes :
  GET  /admin/pending          — liste des comptes en attente
  POST /admin/users/<id>/approve — approuve un compte
  POST /admin/users/<id>/reject  — rejette un compte avec note optionnelle
"""
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from datetime import datetime

from ..models.db import db
from ..models.user import User
from ..models.hospital import Hospital
from ..models.insurer import Insurer
from ..models.patient import Patient
from ..models.proof import Proof
from ..models.verification import Verification
from ..models.audit_log import AuditLog
from ..utils.metrics_collector import get_collector


admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


# ── Guards ───────────────────────────────────────────────────────────────────

def _require_admin(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash("Accès réservé à l'administrateur.", 'danger')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return login_required(wrapper)


def _log(action, desc, resource_type=None, resource_id=None):
    log = AuditLog(
        actor_user_id=current_user.id,
        actor_role='admin',
        action=action,
        description=desc,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id else None,
        ip_address=request.remote_addr,
    )
    db.session.add(log)
    db.session.commit()


# ── Métriques DB ─────────────────────────────────────────────────────────────

def _get_db_metrics():
    vers   = Verification.query.all()
    proofs = Proof.query.all()
    if not vers:
        return {"total": 0, "success_rate": 0, "avg_gen_ms": 0,
                "avg_ver_ms": 0, "avg_size_kb": 0, "records": []}
    n  = len(vers)
    ok = sum(1 for v in vers if v.is_valid)
    avg_ver = sum(v.verification_time_ms for v in vers) / n
    avg_sz  = sum(v.proof_size_bytes for v in vers) / n
    gen_times = [v.proof.generation_time_ms for v in vers if v.proof]
    avg_gen = sum(gen_times) / len(gen_times) if gen_times else 0
    records = []
    for v in sorted(vers, key=lambda x: x.verified_at, reverse=True)[:50]:
        p = v.proof
        records.append({
            "proof_uid": p.proof_uid if p else "—",
            "hospital":  p.hospital.nom if p and p.hospital else "—",
            "insurer":   v.insurer.nom if v.insurer else "—",
            "gen_ms":    round(p.generation_time_ms, 3) if p else 0,
            "ver_ms":    round(v.verification_time_ms, 3),
            "size_bytes": v.proof_size_bytes,
            "valid":     v.is_valid,
            "ts":        v.verified_at.isoformat(),
        })
    return {
        "total": n,
        "success_rate": round(ok / n * 100, 1),
        "avg_gen_ms":   round(avg_gen, 3),
        "avg_ver_ms":   round(avg_ver, 3),
        "avg_size_kb":  round(avg_sz / 1024, 3),
        "records":      records,
    }


# ── Dashboard ─────────────────────────────────────────────────────────────────

@admin_bp.route('/')
@admin_bp.route('/dashboard')
@_require_admin
def dashboard():
    pending_count = User.query.filter_by(status='pending').count()
    stats = {
        'hospitals':          Hospital.query.count(),
        'insurers':           Insurer.query.count(),
        'patients':           Patient.query.count(),
        'proofs':             Proof.query.count(),
        'verifications':      Verification.query.count(),
        'users':              User.query.count(),
        'valid_verifications': Verification.query.filter_by(is_valid=True).count(),
        'pending_count':      pending_count,
    }
    metrics     = _get_db_metrics()
    recent_logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(20).all()
    return render_template('admin/dashboard.html',
                           stats=stats, metrics=metrics,
                           recent_logs=recent_logs,
                           pending_count=pending_count)


# ── Gestion des demandes d'inscription ───────────────────────────────────────

@admin_bp.route('/pending')
@_require_admin
def pending_users():
    """
    Liste tous les comptes en attente d'approbation.
    Affiche également les comptes récemment traités (approuvés/rejetés).
    """
    pending  = (User.query
                .filter_by(status='pending')
                .filter(User.role != 'admin')
                .order_by(User.created_at.desc())
                .all())
    reviewed = (User.query
                .filter(User.status.in_(['active', 'rejected', 'suspended']))
                .filter(User.role != 'admin')
                .order_by(User.reviewed_at.desc())
                .limit(20)
                .all())
    return render_template('admin/pending.html',
                           pending=pending, reviewed=reviewed)


@admin_bp.route('/users/<int:user_id>/approve', methods=['POST'])
@_require_admin
def user_approve(user_id):
    """
    Approuve un compte en attente → status = 'active'.
    """
    user = User.query.get_or_404(user_id)
    if user.role == 'admin':
        flash("Impossible de modifier un compte admin.", 'warning')
        return redirect(url_for('admin.pending_users'))

    if user.status != 'pending':
        flash(f"Ce compte n'est pas en attente (statut : {user.status}).", 'warning')
        return redirect(url_for('admin.pending_users'))

    user.approve(current_user)
    db.session.commit()

    entity_name = (user.hospital.nom if user.hospital
                   else user.insurer.nom if user.insurer
                   else user.email)

    _log('approve_user',
         f"Compte approuvé : {user.email} / {entity_name} [{user.role}]",
         'user', user.id)

    flash(f'✓ Compte de {entity_name} ({user.email}) approuvé avec succès.', 'success')
    return redirect(url_for('admin.pending_users'))


@admin_bp.route('/users/<int:user_id>/reject', methods=['POST'])
@_require_admin
def user_reject(user_id):
    """
    Rejette un compte en attente → status = 'rejected'.
    La note de rejet est optionnelle et sera affichée à l'utilisateur.
    """
    user = User.query.get_or_404(user_id)
    if user.role == 'admin':
        flash("Impossible de modifier un compte admin.", 'warning')
        return redirect(url_for('admin.pending_users'))

    note = request.form.get('rejection_note', '').strip() or None
    user.reject(current_user, note=note)
    db.session.commit()

    entity_name = (user.hospital.nom if user.hospital
                   else user.insurer.nom if user.insurer
                   else user.email)

    _log('reject_user',
         f"Compte rejeté : {user.email} / {entity_name} [{user.role}]"
         + (f" — motif : {note}" if note else ""),
         'user', user.id)

    flash(f'✗ Compte de {entity_name} ({user.email}) rejeté.', 'danger')
    return redirect(url_for('admin.pending_users'))


# ── Reste des routes inchangées ───────────────────────────────────────────────

@admin_bp.route('/users')
@_require_admin
def users_list():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users)


@admin_bp.route('/users/<int:user_id>/toggle')
@_require_admin
def user_toggle(user_id):
    user = User.query.get_or_404(user_id)
    if user.role == 'admin':
        flash('Impossible de désactiver un compte admin.', 'warning')
    else:
        if user.status == 'active':
            user.status = 'suspended'
            flash(f'Compte {user.email} suspendu.', 'warning')
        elif user.status in ('suspended', 'rejected'):
            user.status = 'active'
            flash(f'Compte {user.email} réactivé.', 'success')
        else:
            flash(f'Action non autorisée pour le statut actuel.', 'warning')
        db.session.commit()
    return redirect(url_for('admin.users_list'))

@admin_bp.route('/logs')
@_require_admin
def audit_logs():
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(200).all()
    return render_template('admin/audit_logs.html', logs=logs)


@admin_bp.route('/proofs')
@_require_admin
def proofs_list():
    proofs = Proof.query.order_by(Proof.generated_at.desc()).all()
    return render_template('admin/proofs.html', proofs=proofs)


@admin_bp.route('/metrics')
@_require_admin
def metrics():
    data = _get_db_metrics()
    return render_template('admin/metrics.html', metrics=data)


@admin_bp.route('/hospitals')
@_require_admin
def hospitals_list():
    hospitals = Hospital.query.order_by(Hospital.nom).limit(50).all()
    return render_template('admin/hospitals.html', hospitals=hospitals)


@admin_bp.route('/insurers')
@_require_admin
def insurers_list():
    insurers = Insurer.query.order_by(Insurer.nom).limit(50).all()
    return render_template('admin/insurers.html', insurers=insurers)