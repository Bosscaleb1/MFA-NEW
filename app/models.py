from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    
    # MFA Fields
    mfa_enabled = db.Column(db.Boolean, default=False)
    totp_secret = db.Column(db.String(32), unique=True, nullable=True)
    backup_codes = db.Column(db.Text, nullable=True)  # Stored as comma-separated

    # Passkey (WebAuthn) fields
    passkey_enabled = db.Column(db.Boolean, default=False)
    passkey_credential_id = db.Column(db.Text, nullable=True)
    passkey_public_key = db.Column(db.Text, nullable=True)
    passkey_sign_count = db.Column(db.Integer, default=0)
    
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def setup_totp(self):
        """Generate a new TOTP secret"""
        self.totp_secret = pyotp.random_base32()
        return self.totp_secret
    
    def get_totp_uri(self):
        """Get provisioning URI for QR code"""
        if not self.totp_secret:
            return None
        totp = pyotp.TOTP(self.totp_secret)
        return totp.provisioning_uri(
            name=self.email,
            issuer_name='MFA Auth System'
        )
    
    def verify_totp(self, token):
        """Verify TOTP token"""
        if not self.totp_secret:
            return False
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(token)
    
    def generate_backup_codes(self, count=10):
        """Generate backup codes"""
        import secrets
        codes = [secrets.token_hex(4).upper() for _ in range(count)]
        self.backup_codes = ','.join(codes)
        return codes
    
    def verify_backup_code(self, code):
        """Verify and consume a backup code"""
        if not self.backup_codes:
            return False
        codes = self.backup_codes.split(',')
        if code in codes:
            codes.remove(code)
            self.backup_codes = ','.join(codes)
            return True
        return False

    def has_passkey(self):
        return bool(self.passkey_enabled and self.passkey_credential_id and self.passkey_public_key)

    def clear_passkey(self):
        self.passkey_enabled = False
        self.passkey_credential_id = None
        self.passkey_public_key = None
        self.passkey_sign_count = 0

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
