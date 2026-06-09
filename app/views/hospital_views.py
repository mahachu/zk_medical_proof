"""
Hospital Views — Prouveur ZK
"""
import uuid
import json
from datetime import datetime
from flask import (Blueprint, render_template, request, redirect,
                   url_for, flash, send_file)
from flask_login import login_required, current_user
import io

from ..models.user import User
from ..models.db import db
from ..models.patient import Patient
from ..models.proof import Proof
from ..models.insurer import Insurer
from ..models.audit_log import AuditLog
from ..models.subscription import Subscription
from ..utils.bulletproofs_handler import BulletproofsHandler
from ..utils.decimal_encoder import serialize_proof

hospital_bp = Blueprint('hospital', __name__, url_prefix='/hospital')
_handler = BulletproofsHandler()


def _require_hospital(f):
    """
    Décorateur servant à restreindre l'accès aux utilisateurs connectés 
    ayant le rôle d'hôpital.
    """
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        """
        Vérifie l'état d'authentification et le rôle avant d'exécuter la fonction ciblée.
        """
        if not current_user.is_authenticated or current_user.role != 'hospital':
            flash("Accès réservé à l'hôpital.", 'danger')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return login_required(wrapper)


def _log(action, desc, resource_type=None, resource_id=None):
    """
    Enregistre un événement dans la table d'audit pour assurer la traçabilité 
    des actions de l'hôpital.
    """
    log = AuditLog(
        actor_user_id=current_user.id,
        actor_role='hospital',
        action=action,
        description=desc,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id else None,
        ip_address=request.remote_addr,
    )
    db.session.add(log)
    db.session.commit()


@hospital_bp.route('/')
@hospital_bp.route('/dashboard')
@_require_hospital
def dashboard():
    """
    Affiche le tableau de bord de l'hôpital avec un résumé des patients 
    et des dernières preuves générées.
    """
    h = current_user.hospital
    patients = Patient.query.filter_by(hospital_id=h.id).order_by(Patient.created_at.desc()).all()
    proofs = Proof.query.filter_by(hospital_id=h.id).order_by(Proof.generated_at.desc()).limit(10).all()
    total_proofs = Proof.query.filter_by(hospital_id=h.id).count()
    return render_template('hospital/dashboard.html',
                           hospital=h, patients=patients,
                           proofs=proofs, total_proofs=total_proofs)


@hospital_bp.route('/patients')
@_require_hospital
def patients_list():
    """
    Affiche la liste paginée ou limitée des patients rattachés à l'hôpital connecté.
    """
    h = current_user.hospital
    patients = Patient.query.filter_by(hospital_id=h.id).order_by(Patient.created_at.desc()).limit(50).all()
    return render_template('hospital/patients.html', hospital=h, patients=patients)


@hospital_bp.route('/patients/new', methods=['GET', 'POST'])
@_require_hospital
def patient_new():
    """
    Permet l'ajout d'un nouveau patient au dossier de l'hôpital avec validation des données.
    """
    h = current_user.hospital
    error = None
    if request.method == 'POST':
        nom      = request.form.get('nom', '').strip().upper()
        prenom   = request.form.get('prenom', '').strip().upper()
        age_str  = request.form.get('age', '').strip()
        numero_cni = request.form.get('numero_cni', '').strip().upper()
        temp_str = request.form.get('temperature', '').strip()


        if not nom or not prenom or not age_str or not numero_cni:   
            error = "Nom, prénom, âge et numéro CNI sont obligatoires."

        else:
            try:
                age = int(age_str)
            except ValueError:
                error = "L'âge doit être un entier."
                return render_template('hospital/patient_form.html',
                                       hospital=h, error=error, action='new')
            if temp_str:
                try:
                    temp_val = float(temp_str)
                    if not (0.0 <= temp_val <= 45.0):
                        error = "Température physiologiquement improbable (0–45°C)."
                        return render_template('hospital/patient_form.html',
                                               hospital=h, error=error, action='new')
                except ValueError:
                    error = "Température invalide."
                    return render_template('hospital/patient_form.html',
                                           hospital=h, error=error, action='new')

            patient = Patient(nom=nom, prenom=prenom, age=age,numero_cni=numero_cni,
                              temperature=temp_str if temp_str else None,
                              hospital_id=h.id)
            db.session.add(patient)
            db.session.commit()
            _log('create_patient',
                 f"Nouveau patient : {prenom} {nom} — hôpital {h.nom}",
                 'patient', patient.id)
            flash(f'Patient {prenom} {nom} enregistré avec succès.', 'success')
            return redirect(url_for('hospital.patients_list'))

    return render_template('hospital/patient_form.html',
                           hospital=h, error=error, action='new')


@hospital_bp.route('/patients/<int:patient_id>/edit', methods=['GET', 'POST'])
@_require_hospital
def patient_edit(patient_id):
    """
    Permet l'édition et la mise à jour des informations d'un patient déjà enregistré.
    """
    h = current_user.hospital
    patient = Patient.query.filter_by(id=patient_id, hospital_id=h.id).first_or_404()
    error = None

    if request.method == 'POST':
        patient.nom    = request.form.get('nom', patient.nom).strip().upper()
        patient.prenom = request.form.get('prenom', patient.prenom).strip().upper()
        age_str  = request.form.get('age', str(patient.age)).strip()
        patient.numero_cni = request.form.get('numero_cni', patient.numero_cni).strip().upper()
        temp_str = request.form.get('temperature', '').strip()

        try:
            patient.age = int(age_str)
        except ValueError:
            error = "Âge invalide."
            return render_template('hospital/patient_form.html',
                                   hospital=h, patient=patient, error=error, action='edit')
        if temp_str:
            try:
                temp_val = float(temp_str)
                if not (0.0 <= temp_val <= 45.0):
                    error = "Température hors plage (0–45°C)."
                    return render_template('hospital/patient_form.html',
                                           hospital=h, patient=patient, error=error, action='edit')
                patient.temperature = temp_str
            except ValueError:
                error = "Température invalide."
                return render_template('hospital/patient_form.html',
                                       hospital=h, patient=patient, error=error, action='edit')
        else:
            patient.temperature = None

        db.session.commit()
        _log('update_patient',
             f"Dossier modifié : {patient.prenom} {patient.nom}",
             'patient', patient.id)
        flash('Patient mis à jour.', 'success')
        return redirect(url_for('hospital.patients_list'))

    return render_template('hospital/patient_form.html',
                           hospital=h, patient=patient, error=error, action='edit')


@hospital_bp.route('/generate', methods=['GET', 'POST'])
@_require_hospital
def generate_proof():
    """
    Gère la sélection des paramètres et l'appel au prouveur cryptographique 
    pour générer une preuve ZK relative à la température d'un patient.
    """
    h = current_user.hospital
    patients = Patient.query.filter_by(hospital_id=h.id).order_by(Patient.nom, Patient.prenom).all()
    error = None

    # Patient sélectionné (GET avec param ou rechargement après erreur)
    selected_patient_id = (request.form.get('patient_id', type=int)
                           or request.args.get('patient_id', type=int))

    # Charger les assureurs 
    insurers = []
    if selected_patient_id:
        patient_sel = Patient.query.filter_by(
            id=selected_patient_id, hospital_id=h.id
        ).first()
        if patient_sel:
            # Chercher les souscriptions dont numero_cni correspondent au patient
            subs = Subscription.query.filter_by(
                numero_cni=patient_sel.numero_cni
            ).all()
            insurer_ids = [s.insurer_id for s in subs]
            if insurer_ids:
                insurers = (
                    Insurer.query
                    .join(User, User.insurer_id == Insurer.id)
                    .filter(
                        Insurer.id.in_(insurer_ids),
                        User.role == 'insurer',
                        User.status == 'active'
                    )
                    .order_by(Insurer.nom)
                    .all()
                )

    if request.method == 'POST':
        patient_id = request.form.get('patient_id', type=int)
        insurer_id = request.form.get('insurer_id', type=int)
        temp_str   = request.form.get('temperature', '').strip()

        if not patient_id:
            error = "Sélectionnez un patient."
        elif not insurer_id:
            error = "Sélectionnez un assureur destinataire."
        elif not temp_str:
            error = "La température est manquante."
        else:
            patient = Patient.query.filter_by(id=patient_id, hospital_id=h.id).first()

            # Vérifier que le patient a souscrit chez cet assureur
            sub = Subscription.query.filter_by(
                numero_cni=patient.numero_cni,
                insurer_id=insurer_id
            ).first() 
            insurer = None
            if sub:
                insurer = (
                    Insurer.query
                    .join(User, User.insurer_id == Insurer.id)
                    .filter(
                        Insurer.id == insurer_id,
                        User.role == 'insurer',
                        User.status == 'active'
                    )
                    .first()
                )

            if not patient:
                error = "Patient introuvable."
            elif not sub:
                error = "Ce patient n'a pas souscrit chez l'assureur sélectionné."
            elif not insurer:
                error = "Assureur introuvable ou inactif."
            else:
                try:
                    temp_val = float(temp_str)
                except ValueError:
                    error = "Température invalide."
                    return render_template('hospital/generate_proof.html',
                                           hospital=h, patients=patients,
                                           insurers=insurers,
                                           selected_patient_id=selected_patient_id,
                                           error=error)

                patient.temperature = temp_str
                db.session.commit()

                try:
                    proof_data = _handler.generate(temp_val)
                except ValueError as e:
                    error = str(e)
                    return render_template('hospital/generate_proof.html',
                                           hospital=h, patients=patients,
                                           insurers=insurers,
                                           selected_patient_id=selected_patient_id,
                                           error=error)

                proof_uid = str(uuid.uuid4()).upper()
                proof_json_str = serialize_proof(proof_data)
                size_bytes = len(proof_json_str.encode('utf-8'))

                proof = Proof(
                    proof_uid=proof_uid,
                    patient_id=patient.id,
                    hospital_id=h.id,
                    target_insurer_id=insurer.id,
                    predicate='temperature < 38°C',
                    threshold='38.0',
                    commitment_w=proof_data.get('commitment_w', ''),
                    proof_json=proof_json_str,
                    proof_size_bytes=size_bytes,
                    generation_time_ms=proof_data.get('generation_time_ms', 0.0),
                )
                db.session.add(proof)
                db.session.commit()

                _log('generate_proof',
                     f"Preuve ZK générée pour {patient.nom} {patient.prenom} "
                     f"→ {insurer.nom}",
                     'proof', proof_uid)

                flash(f'Preuve ZK générée et envoyée à {insurer.nom} !', 'success')
                return redirect(url_for('hospital.proof_detail', proof_uid=proof_uid))

    return render_template('hospital/generate_proof.html',
                           hospital=h,
                           patients=patients,
                           insurers=insurers,
                           selected_patient_id=selected_patient_id,
                           error=error)


@hospital_bp.route('/proof/<proof_uid>')
@_require_hospital
def proof_detail(proof_uid):
    """
    Affiche les détails d'une preuve ZK générée par l'hôpital ainsi que son statut de vérification.
    """
    h = current_user.hospital
    proof = Proof.query.filter_by(proof_uid=proof_uid, hospital_id=h.id).first_or_404()
    patient = proof.patient
    verification = proof.verifications.first()
    return render_template('hospital/proof_detail.html',
                           hospital=h, proof=proof, patient=patient,
                           verification=verification)


@hospital_bp.route('/proof/<proof_uid>/download')
@_require_hospital
def proof_download(proof_uid):
    """
    Génère et transmet un fichier JSON téléchargeable contenant la preuve ZK et 
    ses métadonnées associées.
    """
    h = current_user.hospital
    proof = Proof.query.filter_by(proof_uid=proof_uid, hospital_id=h.id).first_or_404()
    proof.is_downloaded = True
    db.session.commit()
    _log('download_proof',
         f"Téléchargement preuve {proof_uid[:8]}…",
         'proof', proof_uid)
    export = {
        "proof_uid": proof.proof_uid,
        "predicate": proof.predicate,
        "threshold": proof.threshold,
        "commitment_w": proof.commitment_w,
        "proof_data": json.loads(proof.proof_json),
        "generated_at": proof.generated_at.isoformat(),
        "hospital_id": h.id,
        "hospital_nom": h.nom,
        "note": "Cette preuve ne contient pas la valeur réelle de la température.",
    }
    content = serialize_proof(export).encode('utf-8')
    return send_file(
        io.BytesIO(content),
        mimetype='application/json',
        as_attachment=True,
        download_name=f"preuve_zk_{proof_uid[:8]}.json",
    )


@hospital_bp.route('/proofs')
@_require_hospital
def proofs_list():
    """
    Affiche la liste de l'ensemble des preuves ZK émises par l'hôpital connecté.
    """
    h = current_user.hospital
    proofs = (Proof.query.filter_by(hospital_id=h.id)
              .order_by(Proof.generated_at.desc()).all())
    return render_template('hospital/proofs_list.html', hospital=h, proofs=proofs)