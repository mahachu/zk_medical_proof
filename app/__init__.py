"""
ZK Medical Proof — Application Factory

Ajout : context_processor inject_pending_count
→ rend `pending_count` disponible dans TOUS les templates,
  ce qui permet au badge rouge dans la sidebar admin de s'afficher
  sur toutes les pages admin sans modification individuelle de chaque vue.
"""
import os
from flask import Flask, redirect, url_for, render_template, request, flash
from flask_login import LoginManager
from .models.db import db
from .models.user import User

login_manager = LoginManager()


def create_app(config_name: str = 'default') -> Flask:
    app = Flask(
        __name__,
        template_folder='views/templates',
        static_folder='../static',
    )

    # Configuration
    from config.settings import config
    app.config.from_object(config[config_name])

    # Initialisation DB
    db.init_app(app)

    # Flask-Login
    login_manager.init_app(app)
    login_manager.login_message = 'Veuillez vous connecter pour accéder à cette page.'
    login_manager.login_message_category = 'warning'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    @login_manager.unauthorized_handler
    def unauthorized():
        return redirect(url_for('auth.login'))

    # ── Context processor global ──────────────────────────────────────────
    # Injecte pending_count dans tous les templates pour le badge sidebar admin
    @app.context_processor
    def inject_pending_count():
        try:
            count = User.query.filter_by(status='pending').count()
        except Exception:
            count = 0
        return dict(pending_count=count)

    # Blueprints
    from .views.auth_views import auth_bp
    from .views.hospital_views import hospital_bp
    from .views.insurer_views import insurer_bp
    from .views.admin_views import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(hospital_bp)
    app.register_blueprint(insurer_bp)
    app.register_blueprint(admin_bp)

    @app.route('/')
    def index():
        return redirect(url_for('auth.login'))
    

    # Ajouter ces 3 routes juste en dessous :
    @app.route('/documentation')
    def documentation():
        return render_template('documentation.html')

    @app.route('/a-propos')
    def a_propos():
        return render_template('a_propos.html')

    @app.route('/contact', methods=['GET', 'POST'])
    def contact():
        if request.method == 'POST':
            prenom  = request.form.get('prenom', '').strip()
            nom     = request.form.get('nom', '').strip()
            email   = request.form.get('email', '').strip()
            sujet   = request.form.get('sujet', '').strip()
            message = request.form.get('message', '').strip()
            role    = request.form.get('role', '').strip()
            msg_type = request.form.get('msg-type', '').strip()

            try:
                import smtplib
                from email.mime.text import MIMEText
                from email.mime.multipart import MIMEMultipart

                smtp_user     = app.config['MAIL_USERNAME']
                smtp_password = app.config['MAIL_PASSWORD']
                smtp_receiver = app.config['MAIL_RECEIVER']

                mail = MIMEMultipart()
                mail['From']    = smtp_user
                mail['To']      = smtp_receiver
                mail['Subject'] = f"[ZK Medical] {sujet}"

                body = f"""
    Nouveau message via le formulaire de contact ZK Medical.

    Expéditeur : {prenom} {nom}
    Email       : {email}
    Rôle        : {role or 'non précisé'}
    Type        : {msg_type}

    Message :
    {message}
                """
                mail.attach(MIMEText(body, 'plain'))

                with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                    server.login(smtp_user, smtp_password)
                    server.sendmail(smtp_user, smtp_receiver, mail.as_string())

                flash('✅ Message envoyé avec succès !', 'success')
            except Exception as e:
                flash(f'❌ Erreur lors de l\'envoi : {str(e)}', 'danger')

            return redirect(url_for('contact'))

        return render_template('contact.html')

    # Création des tables + seed admin
    with app.app_context():
        os.makedirs(
            os.path.join(os.path.dirname(os.path.dirname(__file__)), 'instance'),
            exist_ok=True
        )
        db.create_all()
        _seed_admin()

    # Erreurs
    @app.errorhandler(404)
    def not_found(e):
        return _err_html(404, "Page introuvable"), 404

    @app.errorhandler(500)
    def server_error(e):
        return _err_html(500, f"Erreur serveur : {e}"), 500

    return app


def _seed_admin():
    """
    Crée le compte admin par défaut s'il n'existe pas.
    Le compte admin est directement status='active' — pas de validation nécessaire.
    """
    if not User.query.filter_by(role='admin').first():
        admin = User(email='admin@zkmedical.cm', role='admin', status='active')
        admin.set_password('Admin@2024!')
        db.session.add(admin)
        db.session.commit()


def _err_html(code: int, msg: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="fr">
<head><meta charset="UTF-8"><title>Erreur {code}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#f4f3ef;color:#0f1a14;font-family:'JetBrains Mono',monospace;
display:flex;align-items:center;justify-content:center;min-height:100vh}}
.box{{text-align:center;padding:3rem;border:2px solid #0f1a14;border-radius:8px;max-width:400px}}
.code{{font-size:4rem;font-weight:900;color:#2d6a4f;margin-bottom:1rem}}
p{{color:#6b7c72;margin:0.5rem 0 2rem}}
a{{background:#0f1a14;color:#fff;padding:0.75rem 1.5rem;text-decoration:none;
   font-size:0.85rem;letter-spacing:0.1em;border-radius:6px}}
</style></head>
<body><div class="box">
<div class="code">{code}</div>
<h2>{msg}</h2>
<p>Une erreur s'est produite.</p>
<a href="/">← Retour</a>
</div></body></html>"""
