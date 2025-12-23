import os
import secrets
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Contract(db.Model):
    __tablename__ = 'contracts'
    
    id = db.Column(db.Integer, primary_key=True)
    client_name = db.Column(db.String(200), nullable=False)
    contact_email = db.Column(db.String(120), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    appliances = db.relationship('Appliance', backref='contract', lazy='dynamic', cascade='all, delete-orphan')
    
    @property
    def is_valid(self):
        today = datetime.utcnow().date()
        return self.is_active and self.start_date <= today <= self.end_date

class Appliance(db.Model):
    __tablename__ = 'appliances'
    
    id = db.Column(db.Integer, primary_key=True)
    contract_id = db.Column(db.Integer, db.ForeignKey('contracts.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False)
    description = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    last_seen = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    metrics = db.relationship('Metric', backref='appliance', lazy='dynamic', cascade='all, delete-orphan')
    login_logs = db.relationship('LoginLog', backref='appliance', lazy='dynamic', cascade='all, delete-orphan')
    threat_metadata = db.relationship('ThreatMetadata', backref='appliance', lazy='dynamic', cascade='all, delete-orphan')
    
    @staticmethod
    def generate_token():
        return secrets.token_hex(32)
    
    def reset_token(self):
        self.token = self.generate_token()
        return self.token

class Metric(db.Model):
    __tablename__ = 'metrics'
    
    id = db.Column(db.Integer, primary_key=True)
    appliance_id = db.Column(db.Integer, db.ForeignKey('appliances.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    cpu_percent = db.Column(db.Float)
    memory_percent = db.Column(db.Float)
    memory_used_gb = db.Column(db.Float)
    memory_total_gb = db.Column(db.Float)
    disk_percent = db.Column(db.Float)
    disk_used_gb = db.Column(db.Float)
    disk_total_gb = db.Column(db.Float)
    network_bytes_sent = db.Column(db.BigInteger)
    network_bytes_recv = db.Column(db.BigInteger)
    network_bytes_sent_rate = db.Column(db.Float)
    network_bytes_recv_rate = db.Column(db.Float)

class LoginLog(db.Model):
    __tablename__ = 'login_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    appliance_id = db.Column(db.Integer, db.ForeignKey('appliances.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    login_type = db.Column(db.String(10), nullable=False)
    username = db.Column(db.String(100))
    source_ip = db.Column(db.String(45))
    success = db.Column(db.Boolean, default=True)
    details = db.Column(db.Text)

class ThreatMetadata(db.Model):
    __tablename__ = 'threat_metadata'
    
    id = db.Column(db.Integer, primary_key=True)
    appliance_id = db.Column(db.Integer, db.ForeignKey('appliances.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    threat_type = db.Column(db.String(50))
    severity = db.Column(db.String(20))
    source_ip = db.Column(db.String(45))
    destination_ip = db.Column(db.String(45))
    count = db.Column(db.Integer, default=1)
    metadata_json = db.Column(db.Text)
