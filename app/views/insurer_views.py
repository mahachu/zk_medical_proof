"""
Insurer Views — Vérifieur ZK

Blueprint Flask gérant toutes les routes de l'interface assureur :
tableau de bord, gestion des assurés, vérification des preuves ZK
et téléchargement.
"""
import json
import io
from flask import send_file
import uuid
from flask import (Blueprint, render_template, request,
                   redirect, url_for, flash)
from flask_login import login_required, current_user
from ..models.db import db
from ..models.proof import Proof
from ..models.patient import Patient
from ..models.verification import Verification
from ..models.audit_log import AuditLog
from ..models.subscription import Subscription
from ..utils.bulletproofs_handler import BulletproofsHandler
from ..utils.decimal_encoder import deserialize_proof
from ..utils.metrics_collector import get_collector

insurer_bp = Blueprint('insurer', __name__, url_prefix='/insurer')
_handler = BulletproofsHandler()


def _require_insurer(f):
    """
    Décorateur pour restreindre l'accès aux utilisateurs connectés 
    possédant le rôle d'assureur.
    """
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        """
        Vérifie l'authentification et le rôle avant d'autoriser l'accès à la route.
        """
        if not current_user.is_authenticated or current_user.role != 'insurer':
            flash("Accès réservé à l'assureur.", 'danger')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return login_required(wrapper)


def _log(action, desc, resource_type=None, resource_id=None):
    """
    Enregistre une action effectuée par l'assureur dans les journaux d'audit.
    """
    log = AuditLog(
        actor_user_id=current_user.id,
        actor_role='insurer',
        action=action,
        description=desc,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id else None,
        ip_address=request.remote_addr,
    )
    db.session.add(log)
    db.session.commit()


# ── Dashboard ─────────────────────────────────────────────────────────────────

@insurer_bp.route('/')
@insurer_bp.route('/dashboard')
@_require_insurer
def dashboard():
    """
    Affiche le tableau de bord de l'assureur contenant les statistiques clés,
    les dernières vérifications et les preuves disponibles non encore vérifiées.
    """
    ins = current_user.insurer
    verifications = (Verification.query
                     .filter_by(insurer_id=ins.id)
                     .order_by(Verification.verified_at.desc())
                     .limit(10).all())
    total_ver = Verification.query.filter_by(insurer_id=ins.id).count()
    valid_ver = Verification.query.filter_by(insurer_id=ins.id, is_valid=True).count()
    total_assures = Subscription.query.filter_by(insurer_id=ins.id).count()

    verified_proof_ids = [v.proof_id for v in
                          Verification.query.filter_by(insurer_id=ins.id).all()]
    query = Proof.query.filter_by(target_insurer_id=ins.id)
    if verified_proof_ids:
        query = query.filter(Proof.id.notin_(verified_proof_ids))
    available_proofs = query.order_by(Proof.generated_at.desc()).all()

    return render_template('insurer/dashboard.html',
                           insurer=ins,
                           verifications=verifications,
                           total_ver=total_ver,
                           valid_ver=valid_ver,
                           total_assures=total_assures,
                           available_proofs=available_proofs)


# ── Gestion des assurés ───────────────────────────────────────────────────────
@insurer_bp.route('/assures')
@_require_insurer
def assures_list():
    ins = current_user.insurer
    assures = (Subscription.query
               .filter_by(insurer_id=ins.id)
               .order_by(Subscription.created_at.desc())
               .all())
    return render_template('insurer/assures_list.html',
                           insurer=ins,
                           assures=assures)


@insurer_bp.route('/assures/new', methods=['GET', 'POST'])
@_require_insurer
def assure_new():
    ins = current_user.insurer
    error = None

    if request.method == 'POST':
        nom = request.form.get('nom', '').strip().upper()
        prenom = request.form.get('prenom', '').strip().upper()
        numero_contrat = request.form.get('numero_contrat', '').strip().upper() or None
        numero_cni = request.form.get('numero_cni', '').strip().upper()

        if not nom or not prenom or not numero_cni:
            error = "Le nom, le prénom et le numéro CNI sont obligatoires."
        else:
            sub = Subscription(
                insurer_id=ins.id,
                nom=nom,
                prenom=prenom,
                numero_contrat=numero_contrat,
                numero_cni=numero_cni
            )
            db.session.add(sub)
            db.session.commit()
            _log('add_assure',
                 f"Nouvel assuré : {prenom} {nom}",
                 'subscription', sub.id)
            flash(f'✓ {prenom} {nom} enregistré(e) comme assuré(e).', 'success')
            return redirect(url_for('insurer.assures_list'))

    return render_template('insurer/assure_new.html',
                           insurer=ins,
                           error=error)


@insurer_bp.route('/assures/<int:sub_id>/delete', methods=['POST'])
@_require_insurer
def assure_delete(sub_id):
    ins = current_user.insurer
    sub = Subscription.query.filter_by(id=sub_id, insurer_id=ins.id).first_or_404()
    nom_complet = sub.full_name()
    db.session.delete(sub)
    db.session.commit()
    _log('remove_assure',
         f"Assuré retiré : {nom_complet}",
         'subscription', sub_id)
    flash(f'Assuré(e) {nom_complet} retiré(e).', 'info')
    return redirect(url_for('insurer.assures_list'))


@insurer_bp.route('/assures/<int:sub_id>/edit', methods=['GET', 'POST'])
@_require_insurer
def assure_edit(sub_id):
    ins = current_user.insurer
    sub = Subscription.query.filter_by(id=sub_id, insurer_id=ins.id).first_or_404()
    error = None

    if request.method == 'POST':
        nom = request.form.get('nom', '').strip().upper()
        prenom = request.form.get('prenom', '').strip().upper()
        numero_contrat = request.form.get('numero_contrat', '').strip().upper() or None
        numero_cni = request.form.get('numero_cni', '').strip().upper()

        if not nom or not prenom or not numero_cni:
            error = "Le nom, le prénom et le numéro CNI sont obligatoires."
        else:
            sub.nom = nom
            sub.prenom = prenom
            sub.numero_contrat = numero_contrat
            sub.numero_cni = numero_cni
            db.session.commit()
            _log('edit_assure',
                 f"Assuré modifié : {prenom} {nom}",
                 'subscription', sub.id)
            flash(f'✓ {prenom} {nom} mis à jour.', 'success')
            return redirect(url_for('insurer.assures_list'))

    return render_template('insurer/assure_edit.html',
                           insurer=ins,
                           sub=sub,
                           error=error)

# ── Vérification des preuves ──────────────────────────────────────────────────

@insurer_bp.route('/verify', methods=['GET', 'POST'])
@_require_insurer
def verify():
    """
    Gère la réception et le traitement de la vérification cryptographique d'une preuve ZK.
    """
    ins = current_user.insurer
    error = None

    verified_proof_ids = [v.proof_id for v in
                          Verification.query.filter_by(insurer_id=ins.id).all()]
    query = Proof.query.filter_by(target_insurer_id=ins.id)
    if verified_proof_ids:
        query = query.filter(Proof.id.notin_(verified_proof_ids))
    available_proofs = query.order_by(Proof.generated_at.desc()).all()

    if request.method == 'POST':
        proof_uid = request.form.get('proof_uid', '').strip()
        proof = Proof.query.filter_by(
            proof_uid=proof_uid,
            target_insurer_id=ins.id
        ).first()

        if not proof:
            error = f"Aucune preuve trouvée avec l'identifiant '{proof_uid}' pour votre compte."
        else:
            try:
                proof_data = deserialize_proof(proof.proof_json)
                result = _handler.verify(proof_data)
            except Exception as e:
                result = {
                    "is_valid": False,
                    "range_proof_valid": False,
                    "knowledge_proof_valid": False,
                    "predicate_satisfied": False,
                    "verification_time_ms": 0.0,
                    "error": str(e),
                }

            ver_uid = str(uuid.uuid4()).upper()
            ver = Verification(
                verification_uid=ver_uid,
                proof_id=proof.id,
                insurer_id=ins.id,
                is_valid=result['is_valid'],
                predicate_satisfied=result['predicate_satisfied'],
                range_proof_valid=result['range_proof_valid'],
                knowledge_proof_valid=result['knowledge_proof_valid'],
                error_message=result.get('error'),
                verification_time_ms=result['verification_time_ms'],
                proof_size_bytes=proof.proof_size_bytes,
            )
            db.session.add(ver)
            db.session.commit()

            if result['is_valid']:
                flash('✓ Preuve VALIDE — le prédicat température < 38°C est confirmé.', 'success')
            else:
                flash('✗ Preuve INVALIDE — le prédicat ne peut pas être confirmé.', 'danger')

            collector = get_collector()
            hosp = proof.hospital
            collector.record(
                proof_uid=proof_uid,
                hospital_name=hosp.nom if hosp else '?',
                insurer_name=ins.nom,
                generation_time_ms=proof.generation_time_ms,
                verification_time_ms=result['verification_time_ms'],
                proof_size_bytes=proof.proof_size_bytes,
                is_valid=result['is_valid'],
            )

            status = 'VALIDE' if result['is_valid'] else 'INVALIDE'
            _log('verify_proof',
                 f"Vérification de preuve — résultat : {status}",
                 'verification', ver_uid)

            return redirect(url_for('insurer.verification_detail', ver_uid=ver_uid))

    return render_template('insurer/verify.html',
                           insurer=ins,
                           available_proofs=available_proofs,
                           error=error)


@insurer_bp.route('/verification/<ver_uid>')
@_require_insurer
def verification_detail(ver_uid):
    """
    Affiche le rapport détaillé d'une vérification de preuve spécifique.
    """
    ins = current_user.insurer
    ver = Verification.query.filter_by(
        verification_uid=ver_uid, insurer_id=ins.id
    ).first_or_404()
    proof = ver.proof
    return render_template('insurer/verification_detail.html',
                           insurer=ins, ver=ver, proof=proof)


@insurer_bp.route('/verifications')
@_require_insurer
def verifications_list():
    """
    Affiche l'historique complet des vérifications réalisées par l'assureur.
    """
    ins = current_user.insurer
    vers = (Verification.query.filter_by(insurer_id=ins.id)
            .order_by(Verification.verified_at.desc()).all())
    return render_template('insurer/verifications_list.html',
                           insurer=ins, verifications=vers)


@insurer_bp.route('/proof/download/<proof_uid>')
@_require_insurer
def download_proof(proof_uid):
    """
    Permet le téléchargement au format JSON des données brutes d'une preuve ZK spécifique.
    """
    ins = current_user.insurer
    proof = Proof.query.filter_by(
        proof_uid=proof_uid,
        target_insurer_id=ins.id
    ).first_or_404()

    proof_data = deserialize_proof(proof.proof_json)
    json_bytes = json.dumps(proof_data, indent=2, ensure_ascii=False).encode('utf-8')

    _log('download_proof',
         f"Téléchargement de la preuve {proof_uid[:8]}…",
         'proof', proof_uid)

    return send_file(
        io.BytesIO(json_bytes),
        mimetype='application/json',
        as_attachment=True,
        download_name=f'preuve_zk_{proof_uid[:8]}.json',
    )