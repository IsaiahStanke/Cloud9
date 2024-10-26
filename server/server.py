from flask import Flask, request, jsonify, render_template, redirect, url_for, send_from_directory, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman  # Enforce HTTPS and security headers
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect  # Import CSRF protection
from redis import Redis
from marshmallow import Schema, fields, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
import os
import datetime
import sys
from datetime import timedelta, timezone, datetime
import time
from flask_login import UserMixin
from werkzeug.utils import safe_join
from flask import send_from_directory, jsonify, current_app

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Change this in production

# Enable CSRF Protection
csrf = CSRFProtect(app)  # Initialize CSRF protection

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirect to the login page if user is not authenticated

# Define a custom CSP that allows scripts and styles from specific sources
csp = {
    'default-src': "'self'",
    'script-src': "'self' 'unsafe-inline' https://cdn.jsdelivr.net",
    'style-src': "'self' 'unsafe-inline' https://cdn.jsdelivr.net"
}

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,  # Only if using HTTPS
    SESSION_COOKIE_SAMESITE='Strict'  # Or 'Strict' for stronger protection
)

# PostgreSQL database configuration for app data
DATABASE_URI = 'postgresql://user:password@localhost/detection_data'
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Flask-Talisman for enforcing HTTPS and security headers
Talisman(app, content_security_policy=csp)

# Redis connection for rate limiting
redis_store = Redis(host='localhost', port=6379, decode_responses=True)

# Limiter configuration using Redis
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="redis://localhost:6379"  # Redis for rate limiting storage
)

# Define database models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(300), nullable=False)

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Detection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    detection_type = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text, nullable=False)
    hostname = db.Column(db.String(100), nullable=False)
    src_ip = db.Column(db.String(45))
    dst_ip = db.Column(db.String(45))
    ports_scanned = db.Column(db.ARRAY(db.Integer))
    timestamp = db.Column(db.String(50), nullable=False)

class ScheduledTask(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.String(50), nullable=False)

class HostsFileEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(100), nullable=False)
    non_default_entries = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.String(50), nullable=False)

# New model to store non-Microsoft service data
class NonMicrosoftService(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.String(50), nullable=False)

# Initialize the database
with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME = timedelta(minutes=30)

@app.route('/download/main.py', methods=['GET'])
def download_main_py():
    try:
        # Print current working directory for debugging purposes
        print("Current working directory:", os.getcwd(), flush=True)

        # Adjusted to point to the correct path based on your directory structure
        return send_from_directory('src', 'main.py', as_attachment=True)
    except Exception as e:
        print(f"Error serving main.py: {e}", flush=True)
        return jsonify({"status": "error", "message": "File not found"}), 404

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'failed_attempts' in session:
        failed_attempts = session.get('failed_attempts', 0)
        lockout_timestamp = session.get('lockout_timestamp', None)

        if lockout_timestamp:
            lockout_timestamp = lockout_timestamp.replace(tzinfo=None)
            lockout_duration = datetime.now() - lockout_timestamp
            if lockout_duration < LOCKOUT_TIME:
                remaining_time = LOCKOUT_TIME - lockout_duration
                flash(f'Too many failed attempts. Try again after {remaining_time.seconds // 60} minutes.', 'danger')
                return render_template('login.html')
            else:
                session.pop('failed_attempts', None)
                session.pop('lockout_timestamp', None)

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session.pop('failed_attempts', None)
            session.pop('lockout_timestamp', None)
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            session['failed_attempts'] = session.get('failed_attempts', 0) + 1

            if session['failed_attempts'] >= MAX_LOGIN_ATTEMPTS:
                session['lockout_timestamp'] = datetime.now()
                flash('Too many failed login attempts. You are locked out for 30 minutes.', 'danger')
            else:
                remaining_attempts = MAX_LOGIN_ATTEMPTS - session['failed_attempts']
                flash(f'Invalid username or password. {remaining_attempts} attempts left.', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html')

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)

@app.before_request
def make_session_permanent():
    session.permanent = True

@app.route('/clear', methods=['POST'])
@limiter.limit("5 per minute")
@login_required
@csrf.exempt  # Disable CSRF for this endpoint
def clear_data():
    try:
        db.session.query(Detection).delete()
        db.session.query(ScheduledTask).delete()
        db.session.query(HostsFileEntry).delete()  # Clear hosts file entries
        db.session.query(NonMicrosoftService).delete()  # Clear non-Microsoft services
        db.session.commit()
        flash('Entries Cleared', 'success')
        return redirect(url_for('dashboard'))
    except Exception as e:
        print(f"Error clearing data: {e}", flush=True)
        flash('Error clearing data', 'danger')
        return jsonify({"status": "error", "message": "An error occurred"}), 500

@app.route('/data', methods=['POST'])
@limiter.limit("10 per minute")
@csrf.exempt  # Disable CSRF for this endpoint
def receive_data():
    try:
        print(f"Raw data received: {request.data}", flush=True)  # Print raw data
        data = request.get_json(silent=True)  # Use get_json to avoid exceptions
        if data is None:
            print("Failed to parse JSON or no data was received.", flush=True)
            return jsonify({"status": "error", "message": "Invalid or missing data"}), 400

        # Insert the received data into the Detection table
        new_detection = Detection(
            detection_type=data.get('detection_type', 'Unknown'),
            details=data.get('details', ''),
            hostname=data.get('hostname', 'Unknown'),
            src_ip=data.get('src_ip', 'Unknown'),
            dst_ip=data.get('dst_ip', 'Unknown'),
            ports_scanned=data.get('ports_scanned', []),
            timestamp=data.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )

        db.session.add(new_detection)
        db.session.commit()

        print(f"Received and inserted data: {data}", flush=True)
        return jsonify({"status": "success"}), 200
    except ValidationError as err:
        return jsonify({"status": "error", "message": err.messages}), 400
    except Exception as e:
        print(f"Error processing request: {e}", flush=True)
        return jsonify({"status": "error", "message": "An error occurred"}), 500

# POST endpoint to receive scheduled task data
@app.route('/scheduled_tasks', methods=['POST'])
@limiter.limit("10 per minute")
@csrf.exempt  # Disable CSRF for this endpoint
def receive_scheduled_tasks():
    try:
        data = request.json
        print(f"Received scheduled tasks data: {data}", flush=True)  # Added print statement for debugging
        if not data:
            return jsonify({"status": "error", "message": "Invalid or missing data"}), 400

        # Insert the received data into the ScheduledTask table
        new_task = ScheduledTask(
            hostname=data.get('hostname', 'Unknown'),
            details=data.get('details', ''),
            timestamp=data.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )

        db.session.add(new_task)
        db.session.commit()

        print(f"Received and inserted scheduled task data: {data}", flush=True)
        return jsonify({"status": "success"}), 200
    except ValidationError as err:
        return jsonify({"status": "error", "message": err.messages}), 400
    except Exception as e:
        print(f"Error processing request: {e}", flush=True)
        return jsonify({"status": "error", "message": "An error occurred"}), 500

@app.route('/hosts_entries', methods=['POST'])
@limiter.limit("10 per minute")
@csrf.exempt  # Disable CSRF for this endpoint
def receive_hosts_entries():
    try:
        data = request.json
        print(f"Received hosts entries data: {data}", flush=True)  # Debugging print

        if not data:
            return jsonify({"status": "error", "message": "Invalid or missing data"}), 400

        # Insert the received data into the HostsFileEntry table
        new_entry = HostsFileEntry(
            hostname=data.get('hostname', 'Unknown'),
            non_default_entries="\n".join(data.get('non_default_entries', [])),
            timestamp=data.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )

        db.session.add(new_entry)
        db.session.commit()

        print(f"Received and inserted hosts file data: {data}", flush=True)
        return jsonify({"status": "success"}), 200
    except Exception as e:
        print(f"Error processing request: {e}", flush=True)
        return jsonify({"status": "error", "message": "An error occurred"}), 500

# POST endpoint to receive non-Microsoft service data
@app.route('/non_microsoft_services', methods=['POST'])
@limiter.limit("10 per minute")
@csrf.exempt  # Disable CSRF for this endpoint
def receive_non_microsoft_services():
    try:
        data = request.json
        print(f"Received non-Microsoft services data: {data}", flush=True)

        if not data:
            return jsonify({"status": "error", "message": "Invalid or missing data"}), 400

        # Insert the received data into the NonMicrosoftService table
        new_service = NonMicrosoftService(
            hostname=data.get('hostname', 'Unknown'),
            details=data.get('details', ''),
            timestamp=data.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )

        db.session.add(new_service)
        db.session.commit()

        print(f"Received and inserted non-Microsoft services data: {data}", flush=True)
        return jsonify({"status": "success"}), 200
    except Exception as e:
        print(f"Error processing request: {e}", flush=True)
        return jsonify({"status": "error", "message": "An error occurred"}), 500

# GET endpoint for detection data
@app.route('/data', methods=['GET'])
@login_required
@csrf.exempt  # Disable CSRF for this endpoint
def get_data():
    try:
        detections = Detection.query.order_by(Detection.timestamp.desc()).all()
        detection_list = [{
            "detection_type": d.detection_type,
            "details": d.details,
            "hostname": d.hostname,
            "src_ip": d.src_ip,
            "dst_ip": d.dst_ip,
            "ports_scanned": d.ports_scanned,
            "timestamp": d.timestamp
        } for d in detections]
        print(f"Fetched detections from DB: {detection_list}", flush=True)
        return jsonify(detection_list), 200
    except Exception as e:
        print(f"Error fetching data: {e}", flush=True)
        return jsonify({"status": "error", "message": "An error occurred"}), 500

# GET endpoint to retrieve scheduled tasks data
@app.route('/scheduled_tasks', methods=['GET'])
@login_required
@csrf.exempt  # Disable CSRF for this endpoint
def get_scheduled_tasks():
    try:
        tasks = ScheduledTask.query.order_by(ScheduledTask.timestamp.desc()).all()
        task_list = [{
            "hostname": t.hostname,
            "details": t.details,
            "timestamp": t.timestamp
        } for t in tasks]
        print(f"Fetched scheduled tasks from DB: {task_list}", flush=True)
        return jsonify(task_list), 200
    except Exception as e:
        print(f"Error fetching scheduled tasks: {e}", flush=True)
        return jsonify({"status": "error", "message": "An error occurred"}), 500

# GET endpoint to retrieve hosts entries data
@app.route('/hosts_entries', methods=['GET'])
@login_required
@csrf.exempt  # Disable CSRF for this endpoint
def get_hosts_entries():
    try:
        entries = HostsFileEntry.query.order_by(HostsFileEntry.timestamp.desc()).all()
        entry_list = [{
            "hostname": entry.hostname,
            "non_default_entries": entry.non_default_entries,
            "timestamp": entry.timestamp
        } for entry in entries]
        
        print(f"Fetched hosts entries from DB: {entry_list}", flush=True)
        return jsonify(entry_list), 200
    except Exception as e:
        print(f"Error fetching hosts entries: {e}", flush=True)
        return jsonify({"status": "error", "message": "An error occurred"}), 500

# GET endpoint to retrieve non-Microsoft services data
@app.route('/non_microsoft_services', methods=['GET'])
@login_required
@csrf.exempt  # Disable CSRF for this endpoint
def get_non_microsoft_services():
    try:
        services = NonMicrosoftService.query.order_by(NonMicrosoftService.timestamp.desc()).all()
        service_list = [{
            "hostname": s.hostname,
            "details": s.details,
            "timestamp": s.timestamp
        } for s in services]
        print(f"Fetched non-Microsoft services from DB: {service_list}", flush=True)
        return jsonify(service_list), 200
    except Exception as e:
        print(f"Error fetching non-Microsoft services: {e}", flush=True)
        return jsonify({"status": "error", "message": "An error occurred"}), 500

@app.errorhandler(404)
def not_found_error(error):
    return jsonify({"status": "error", "message": "Resource not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"status": "error", "message": "Internal server error"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False, ssl_context=('cert.pem', 'key.pem'))
