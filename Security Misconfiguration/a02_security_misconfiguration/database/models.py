from datetime import datetime
from .db import db

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="user", nullable=False)  # admin/user
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login_at = db.Column(db.DateTime)

    scans = db.relationship("ScanRun", back_populates="user", cascade="all, delete-orphan")
    logs = db.relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")


class ScanRun(db.Model):
    __tablename__ = "scan_runs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)

    target = db.Column(db.String(512), nullable=False)
    scan_type = db.Column(db.String(64), nullable=False)  # A02/headers/services...
    status = db.Column(db.String(32), default="PENDING", nullable=False, index=True)

    started_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    finished_at = db.Column(db.DateTime)

    parameters_json = db.Column(db.Text)     # ex: {"ports":[21,445], "timeout":2}
    summary_json = db.Column(db.Text)        # ex: {"HIGH":2,"MEDIUM":1}
    error_message = db.Column(db.Text)

    user = db.relationship("User", back_populates="scans")
    findings = db.relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    artifacts = db.relationship("Artifact", back_populates="scan", cascade="all, delete-orphan")
    logs = db.relationship("AuditLog", back_populates="scan", cascade="all, delete-orphan")


class Finding(db.Model):
    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan_runs.id"), nullable=False, index=True)

    category = db.Column(db.String(64), nullable=False)    # A02, headers, cookies...
    title = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(16), nullable=False, index=True)  # INFO/LOW/MEDIUM/HIGH/CRITICAL

    description = db.Column(db.Text)
    evidence = db.Column(db.Text)
    recommendation = db.Column(db.Text)

    cwe = db.Column(db.String(32))         # optionnel
    owasp_ref = db.Column(db.String(32))   # optionnel
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    scan = db.relationship("ScanRun", back_populates="findings")


class Artifact(db.Model):
    __tablename__ = "artifacts"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan_runs.id"), nullable=False, index=True)

    type = db.Column(db.String(16), nullable=False)      # pdf/json/...
    path = db.Column(db.Text, nullable=False)
    sha256 = db.Column(db.String(64))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    scan = db.relationship("ScanRun", back_populates="artifacts")


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan_runs.id"), index=True)

    action = db.Column(db.String(64), nullable=False, index=True)
    ip = db.Column(db.String(64))
    user_agent = db.Column(db.Text)
    details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user = db.relationship("User", back_populates="logs")
    scan = db.relationship("ScanRun", back_populates="logs")