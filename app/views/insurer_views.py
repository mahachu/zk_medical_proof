"""
Insurer Views — Vérifieur ZK
 
Blueprint Flask gérant toutes les routes de l'interface assureur :
tableau de bord, vérification des preuves ZK et téléchargement.
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
from ..models.verification import Verification
from ..models.audit_log import AuditLog
from ..utils.bulletproofs_handler import BulletproofsHandler
from ..utils.decimal_encoder import deserialize_proof
from ..utils.metrics_collector import get_collector

insurer_bp = Blueprint('insurer', __name__, url_prefix='/insurer')
_handler = BulletproofsHandler()


def _require_insurer(f):
    """Décorateur : restreint l'accès aux utilisateurs ayant le rôle ``insurer``.
 
    Redirige vers la page de connexion avec un message d'erreur si l'utilisateur
    n'est pas authentifié ou n'a pas le rôle requis.
 
    Args:
        f (callable): La fonction de vue à protéger.
 
    Returns:
        callable: La fonction de vue enveloppée avec la vérification du rôle
        et ``login_required``.
    """

    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'insurer':
            flash('Accès réservé à l\'assureur.', 'danger')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return login_required(wrapper)


def _log(action, desc, resource_type=None, resource_id=None):
    """Enregistre une entrée dans le journal d'audit.
 
    Crée et persiste un ``AuditLog`` associé à l'utilisateur courant,
    à son adresse IP et à la ressource concernée.
 
    Args:
        action (str): Code de l'action effectuée (ex. ``'verify_proof'``).
        desc (str): Description lisible de l'action.
        resource_type (str, optional): Type de la ressource concernée
            (ex. ``'verification'``, ``'proof'``).
        resource_id (optional): Identifiant de la ressource, converti en
            chaîne si fourni.
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


@insurer_bp.route('/')
@insurer_bp.route('/dashboard')
@_require_insurer
def dashboard():
    """Affiche le tableau de bord de l'assureur.
 
    Présente les 10 vérifications les plus récentes, les compteurs globaux
    (total et valides) et la liste des preuves disponibles non encore
    vérifiées par cet assureur.
 
    Returns:
        Response: Rendu du template ``insurer/dashboard.html``.
    """
    ins = current_user.insurer
    verifications = (Verification.query
                     .filter_by(insurer_id=ins.id)
                     .order_by(Verification.verified_at.desc())
                     .limit(10).all())
    total_ver = Verification.query.filter_by(insurer_id=ins.id).count()
    valid_ver = Verification.query.filter_by(insurer_id=ins.id, is_valid=True).count()

    # Preuves envoyées à CET assureur, pas encore vérifiées par lui
    verified_proof_ids = [v.proof_id for v in
                          Verification.query.filter_by(insurer_id=ins.id).all()]
    query = Proof.query.filter_by(target_insurer_id=ins.id)
    if verified_proof_ids:
        query = query.filter(Proof.id.notin_(verified_proof_ids))
    available_proofs = query.order_by(Proof.generated_at.desc()).all()

    return render_template('insurer/dashboard.html',
                           insurer=ins, verifications=verifications,
                           total_ver=total_ver, valid_ver=valid_ver,
                           available_proofs=available_proofs)


@insurer_bp.route('/verify', methods=['GET', 'POST'])
@_require_insurer
def verify():
    """Vérifie une preuve ZK soumise par l'assureur.
 
    GET  : Affiche le formulaire de vérification avec les preuves disponibles.
    POST : Recherche la preuve par ``proof_uid``, appelle
           ``BulletproofsHandler.verify``, persiste le résultat dans
           ``Verification``, enregistre les métriques et journalise l'action.
           En cas d'exception lors de la vérification, un résultat invalide
           est tout de même persisté avec le message d'erreur.
 
    Returns:
        Response: Redirection vers ``verification_detail`` en cas de succès,
        rendu du formulaire avec erreur sinon.
    """

    ins = current_user.insurer
    error = None

    # Preuves envoyées à cet assureur uniquement
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
                           insurer=ins, available_proofs=available_proofs, error=error)


@insurer_bp.route('/verification/<ver_uid>')
@_require_insurer
def verification_detail(ver_uid):
    """Affiche le détail d'une vérification et la preuve associée.
 
    Args:
        ver_uid (str): Identifiant unique de la vérification.
 
    Returns:
        Response: Rendu du template ``insurer/verification_detail.html``.
        Retourne 404 si la vérification n'appartient pas à l'assureur courant.
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
    """Affiche l'historique complet des vérifications de l'assureur.
 
    Returns:
        Response: Rendu du template ``insurer/verifications_list.html``.
    """
    ins = current_user.insurer
    vers = (Verification.query.filter_by(insurer_id=ins.id)
            .order_by(Verification.verified_at.desc()).all())
    return render_template('insurer/verifications_list.html',
                           insurer=ins, verifications=vers)


@insurer_bp.route('/proof/download/<proof_uid>')
@_require_insurer
def download_proof(proof_uid):
    """Télécharge une preuve ZK au format JSON.
 
    Accessible uniquement par l'assureur destinataire de la preuve.
    Journalise le téléchargement avant de retourner le fichier.
 
    Args:
        proof_uid (str): Identifiant unique de la preuve.
 
    Returns:
        Response: Fichier JSON en pièce jointe (``application/json``).
        Retourne 404 si la preuve n'est pas destinée à l'assureur courant.
    """

    ins = current_user.insurer
    proof = Proof.query.filter_by(
        proof_uid=proof_uid,
        target_insurer_id=ins.id
    ).first_or_404()

    proof_data = deserialize_proof(proof.proof_json)
    json_bytes = json.dumps(proof_data, indent=2, ensure_ascii=False).encode('utf-8')

    _log('download_proof',
         f"Téléchargement de la preuve  {proof_uid[:8]}…",
         'proof', proof_uid)

    return send_file(
        io.BytesIO(json_bytes),
        mimetype='application/json',
        as_attachment=True,
        download_name=f'preuve_zk_{proof_uid[:8]}.json',
    )