from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman  # Enforce HTTPS and security headers
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from redis import Redis
from marshmallow import Schema, fields, ValidationError
import os
import datetime
import sys

app = Flask(__name__)

# Define a custom CSP that allows scripts and styles from specific sources
csp = {
    'default-src': "'self'",
    'script-src': "'self' 'unsafe-inline' https://cdn.jsdelivr.net",
    'style-src': "'self' 'unsafe-inline' https://cdn.jsdelivr.net"
}

# PostgreSQL database configuration for app data
DATABASE_URI = 'postgresql://cloud9:$Tr33K1ck55$@localhost/detection_data'
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

# Make sure Python flushes output immediately
sys.stdout.reconfigure(line_buffering=True)

# Define Detection model for PostgreSQL
class Detection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    detection_type = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text, nullable=False)
    hostname = db.Column(db.String(100), nullable=False)
    src_ip = db.Column(db.String(45))  # IP address size limits
    dst_ip = db.Column(db.String(45))
    ports_scanned = db.Column(db.ARRAY(db.Integer))
    timestamp = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return f'<Detection {self.hostname} - {self.detection_type}>'

# Initialize the database
with app.app_context():
    db.create_all()

# Schema for validating incoming data using marshmallow
class DetectionSchema(Schema):
    detection_type = fields.Str(required=True)
    details = fields.Str(required=True)
    hostname = fields.Str(required=True)
    timestamp = fields.Str()
    src_ip = fields.Str()
    dst_ip = fields.Str()
    ports_scanned = fields.List(fields.Int())

detection_schema = DetectionSchema()

# POST endpoint to receive data from the detection functions
@app.route('/data', methods=['POST'])
@limiter.limit("10 per minute")
def receive_data():
    try:
        data = request.json
        if not data:
            return jsonify({"status": "error", "message": "Invalid or missing data"}), 400

        # Validate the data using marshmallow
        detection_schema.load(data)

        # Create a new Detection object
        new_detection = Detection(
            detection_type=data['detection_type'],
            details=data['details'],
            hostname=data['hostname'],
            src_ip=data.get('src_ip'),
            dst_ip=data.get('dst_ip'),
            ports_scanned=data.get('ports_scanned'),
            timestamp=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )

        # Add to the database and commit
        db.session.add(new_detection)
        db.session.commit()

        print(f"Received data: {data}", flush=True)
        return jsonify({"status": "success"}), 200
    except ValidationError as err:
        return jsonify({"status": "error", "message": err.messages}), 400
    except Exception as e:
        print(f"Error processing request: {e}", flush=True)
        return jsonify({"status": "error", "message": "An error occurred"}), 500

# Route to clear the data store
@app.route('/clear', methods=['POST'])
@limiter.limit("5 per minute")
def clear_data():
    try:
        db.session.query(Detection).delete()  # Delete all records
        db.session.commit()
        print("Cleared all data", flush=True)
        return redirect(url_for('dashboard'))
    except Exception as e:
        print(f"Error clearing data: {e}", flush=True)
        return jsonify({"status": "error", "message": "An error occurred"}), 500

# GET endpoint to retrieve data for the dashboard
@app.route('/data', methods=['GET'])
@limiter.limit("20 per minute")
def get_data():
    try:
        detections = Detection.query.order_by(Detection.timestamp.desc()).all()  # Fetch all records, sorted by timestamp
        detection_list = [{
            "detection_type": d.detection_type,
            "details": d.details,
            "hostname": d.hostname,
            "src_ip": d.src_ip,
            "dst_ip": d.dst_ip,
            "ports_scanned": d.ports_scanned,
            "timestamp": d.timestamp
        } for d in detections]

        return jsonify(detection_list), 200
    except Exception as e:
        print(f"Error fetching data: {e}", flush=True)
        return jsonify({"status": "error", "message": "An error occurred"}), 500

# Serve a simple HTML dashboard
@app.route('/')
def dashboard():
    return render_template('dashboard.html')

# Error handling for 404 and 500 errors
@app.errorhandler(404)
def not_found_error(error):
    return jsonify({"status": "error", "message": "Resource not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"status": "error", "message": "Internal server error"}), 500

if __name__ == '__main__':
    # Ensure Flask runs without debug mode in production environments
    app.run(host='0.0.0.0', port=5000, debug=False, ssl_context=('cert.pem', 'key.pem'))
