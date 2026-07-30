from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta
import os
from analyzer import analyze_url, analyze_email
from models import db, User, ScanResult
import cv2
import numpy as np
from gmail_scanner import scan_inbox

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Configuration
app.config['SECRET_KEY'] = 'phishguard-secret-key-2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///phishguard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'jwt-secret-phishguard'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

db.init_app(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# ─── AUTH ROUTES ────────────────────────────────────────────────────────────

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data.get('name', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not name or not email or not password:
        return jsonify({'error': 'All fields are required'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 409

    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
    user = User(name=name, email=email, password=hashed_pw)
    db.session.add(user)
    db.session.commit()

    token = create_access_token(identity=str(user.id))
    return jsonify({'token': token, 'user': user.to_dict()}), 201


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    user = User.query.filter_by(email=email).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({'error': 'Invalid credentials'}), 401

    token = create_access_token(identity=str(user.id))
    return jsonify({'token': token, 'user': user.to_dict()}), 200


@app.route('/api/me', methods=['GET'])
@jwt_required()
def get_me():
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify(user.to_dict())


# ─── SCAN ROUTES ────────────────────────────────────────────────────────────

@app.route('/api/scan/url', methods=['POST'])
@jwt_required()
def scan_url():
    user_id = int(get_jwt_identity())
    data = request.get_json()
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    result = analyze_url(url)

    scan = ScanResult(
        user_id=user_id,
        scan_type='url',
        input_value=url,
        risk_score=result['risk_score'],
        verdict=result['verdict'],
        indicators=str(result['indicators']),
        description=result['description']
    )
    db.session.add(scan)
    db.session.commit()

    return jsonify({**result, 'scan_id': scan.id})


@app.route('/api/scan/email', methods=['POST'])
@jwt_required()
def scan_email():
    user_id = int(get_jwt_identity())
    data = request.get_json()
    content = data.get('content', '').strip()

    if not content:
        return jsonify({'error': 'Email content is required'}), 400

    result = analyze_email(content)

    scan = ScanResult(
        user_id=user_id,
        scan_type='email',
        input_value=content[:200],
        risk_score=result['risk_score'],
        verdict=result['verdict'],
        indicators=str(result['indicators']),
        description=result['description']
    )
    db.session.add(scan)
    db.session.commit()

    return jsonify({**result, 'scan_id': scan.id})


@app.route('/api/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    user_id = int(get_jwt_identity())
    scans = ScanResult.query.filter_by(user_id=user_id).order_by(ScanResult.created_at.desc()).all()

    total = len(scans)
    phishing = sum(1 for s in scans if s.verdict == 'PHISHING')
    safe = sum(1 for s in scans if s.verdict == 'SAFE')
    suspicious = sum(1 for s in scans if s.verdict == 'SUSPICIOUS')

    # Last 7 days activity
    from datetime import datetime, timedelta
    now = datetime.utcnow()
    activity = {}
    for i in range(7):
        day = (now - timedelta(days=i)).strftime('%b %d')
        activity[day] = {'phishing': 0, 'safe': 0, 'suspicious': 0}
    for s in scans:
        day = s.created_at.strftime('%b %d')
        if day in activity:
            activity[day][s.verdict.lower()] = activity[day].get(s.verdict.lower(), 0) + 1

        return jsonify({
        'stats': {
            'total_scans': total,
            'phishing_detected': phishing,
            'safe_scans': safe,
            'suspicious_scans': suspicious,
            'threat_rate': round((phishing / total * 100), 1) if total > 0 else 0,
            'avg_risk': round(sum(s.risk_score for s in scans) / total, 1) if total > 0 else 0
        },
        'recent_scans': [s.to_dict() for s in scans[:10]],
        'activity': activity,
        'risk_distribution': {
            'PHISHING': phishing,
            'SUSPICIOUS': suspicious,
            'SAFE': safe
        }
    })

@app.route('/api/history', methods=['GET'])
@jwt_required()
def history():
    user_id = int(get_jwt_identity())
    scans = ScanResult.query.filter_by(user_id=user_id).order_by(ScanResult.created_at.desc()).all()
    return jsonify([s.to_dict() for s in scans])


@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'service': 'PhishGuard API'})

@app.route('/api/extension/scan', methods=['POST'])
def extension_scan():
    data = request.get_json()
    url = data.get('url', '').strip()

    if not url:
        return jsonify({
            'error': 'URL is required'
        }), 400

    result = analyze_url(url)

    return jsonify({
        'verdict': result.get('verdict', 'UNKNOWN'),
        'confidence': result.get('risk_score', 0),
        'description': result.get('description', ''),
        'indicators': result.get('indicators', [])
    }), 200


@app.route('/api/scan/qr', methods=['POST'])
def scan_qr():
    if 'image' not in request.files:
        return jsonify({'error': 'No image uploaded'}), 400

    file = request.files['image']

    try:
        file_bytes = np.frombuffer(file.read(), np.uint8)
        img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)

        detector = cv2.QRCodeDetector()
        qr_data, bbox, _ = detector.detectAndDecode(img)

        if not qr_data:
            return jsonify({'error': 'No QR code found'}), 400

        result = analyze_url(qr_data)

        return jsonify({
            'decoded_url': qr_data,
            'verdict': result.get('verdict'),
            'confidence': result.get('risk_score'),
            'description': result.get('description'),
            'indicators': result.get('indicators', [])
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/gmail', methods=['GET'])
def scan_gmail():
    try:
        data = scan_inbox(10)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500    

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("✅ Database initialized")
    app.run(debug=True, port=5000)
