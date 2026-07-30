from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='User')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scans = db.relationship('ScanResult', backref='user', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'role': self.role,
            'created_at': self.created_at.isoformat()
        }


class ScanResult(db.Model):
    __tablename__ = 'scan_results'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    scan_type = db.Column(db.String(10), nullable=False)  # 'url' or 'email'
    input_value = db.Column(db.Text, nullable=False)
    risk_score = db.Column(db.Float, nullable=False)
    verdict = db.Column(db.String(20), nullable=False)  # SAFE / SUSPICIOUS / PHISHING
    indicators = db.Column(db.Text, default='[]')
    description = db.Column(db.Text, default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        import ast
        try:
            indicators = ast.literal_eval(self.indicators)
        except:
            indicators = []
        return {
            'id': self.id,
            'scan_type': self.scan_type,
            'input_value': self.input_value,
            'risk_score': self.risk_score,
            'verdict': self.verdict,
            'indicators': indicators,
            'description': self.description,
            'created_at': self.created_at.isoformat()
        }
