import os
import json
import pyotp
import qrcode
from io import BytesIO
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask import current_app
from app.utils.encryption import get_encryption_manager

class User:
    """User model for Key Locker"""

    def __init__(self, username, **kwargs):
        self.username = username
        self.email = kwargs.get('email')
        self.password_hash = kwargs.get('password_hash')
        self.role = kwargs.get('role', 'user')
        self.two_fa_secret = kwargs.get('two_fa_secret')
        self.two_fa_enabled = kwargs.get('two_fa_enabled', False)
        self.ip_whitelist = kwargs.get('ip_whitelist', [])
        self.created_at = kwargs.get('created_at', datetime.utcnow().isoformat())
        self.last_login = kwargs.get('last_login')
        self.login_attempts = kwargs.get('login_attempts', 0)
        self.account_locked = kwargs.get('account_locked', False)
        self.lock_until = kwargs.get('lock_until')

    def set_password(self, password):
        """Hash and set the user password"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Check password and track failed attempts"""
        if self.is_account_locked():
            return False

        if check_password_hash(self.password_hash, password):
            self.login_attempts = 0
            self.last_login = datetime.utcnow().isoformat()
            self.save()
            return True
        else:
            self.login_attempts += 1
            if self.login_attempts >= current_app.config['MAX_LOGIN_ATTEMPTS']:
                self.account_locked = True
                self.lock_until = (datetime.utcnow() +
                                   timedelta(seconds=current_app.config['LOCKOUT_DURATION'])
                                  ).isoformat()
            self.save()
            return False

    def is_account_locked(self):
        """Return True if account is currently locked"""
        if not self.account_locked:
            return False
        if self.lock_until and datetime.fromisoformat(self.lock_until) < datetime.utcnow():
            self.account_locked = False
            self.lock_until = None
            self.login_attempts = 0
            self.save()
            return False
        return True

    def setup_two_factor(self):
        """Generate TOTP secret and QR code for 2FA setup"""
        if not self.two_fa_secret:
            self.two_fa_secret = pyotp.random_base32()

        totp_uri = pyotp.totp.TOTP(self.two_fa_secret).provisioning_uri(
            self.username, issuer_name=current_app.config['APP_NAME']
        )

        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        qr_code_base64 = buffer.getvalue().hex()
        buffer.close()

        return {
            'secret': self.two_fa_secret,
            'qr_code': qr_code_base64,
            'uri': totp_uri
        }

    def verify_totp(self, token):
        """Verify a TOTP token"""
        if not self.two_fa_secret:
            return False
        totp = pyotp.TOTP(self.two_fa_secret)
        return totp.verify(token, valid_window=1)

    def enable_two_factor(self):
        """Enable TOTP-based 2FA"""
        self.two_fa_enabled = True
        self.save()

    def disable_two_factor(self):
        """Disable 2FA and clear secret"""
        self.two_fa_enabled = False
        self.two_fa_secret = None
        self.save()

    def is_ip_allowed(self, ip_address):
        """Return True if IP is in whitelist or whitelist is empty"""
        if not self.ip_whitelist:
            return True
        return ip_address in self.ip_whitelist

    def add_ip_to_whitelist(self, ip_address):
        """Add an IP address to the whitelist"""
        if ip_address not in self.ip_whitelist:
            self.ip_whitelist.append(ip_address)
            self.save()

    def remove_ip_from_whitelist(self, ip_address):
        """Remove an IP address from the whitelist"""
        if ip_address in self.ip_whitelist:
            self.ip_whitelist.remove(ip_address)
            self.save()

    def to_dict(self):
        """Return a dict representation (non-sensitive)"""
        return {
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'two_fa_enabled': self.two_fa_enabled,
            'created_at': self.created_at,
            'last_login': self.last_login,
            'account_locked': self.account_locked
        }

    def save(self):
        """Encrypt and save user data to JSON file"""
        users_file = os.path.join(
            current_app.config['DATA_DIR'], 'encrypted', 'users.json.enc'
        )

        users_data = {}
        if os.path.exists(users_file):
            try:
                encrypted = open(users_file, 'r').read()
                users_data = get_encryption_manager().decrypt_data(encrypted)
            except Exception:
                users_data = {}

        users_data[self.username] = {
            'password_hash': self.password_hash,
            'email': self.email,
            'role': self.role,
            'two_fa_secret': self.two_fa_secret,
            'two_fa_enabled': self.two_fa_enabled,
            'ip_whitelist': self.ip_whitelist,
            'created_at': self.created_at,
            'last_login': self.last_login,
            'login_attempts': self.login_attempts,
            'account_locked': self.account_locked,
            'lock_until': self.lock_until
        }

        encrypted_data = get_encryption_manager().encrypt_data(users_data)
        os.makedirs(os.path.dirname(users_file), exist_ok=True)
        with open(users_file, 'w') as f:
            f.write(encrypted_data)

    @classmethod
    def get(cls, username):
        """Load and decrypt a user by username"""
        users_file = os.path.join(
            current_app.config['DATA_DIR'], 'encrypted', 'users.json.enc'
        )
        if os.path.exists(users_file):
            try:
                encrypted = open(users_file, 'r').read()
                data = get_encryption_manager().decrypt_data(encrypted)
                if username in data:
                    return cls(username, **data[username])
            except Exception:
                current_app.logger.error(f"Error loading user {username}")
        return None

    @classmethod
    def get_all_users(cls):
        """Load and return all users"""
        users_file = os.path.join(
            current_app.config['DATA_DIR'], 'encrypted', 'users.json.enc'
        )
        users = []
        if os.path.exists(users_file):
            try:
                encrypted = open(users_file, 'r').read()
                data = get_encryption_manager().decrypt_data(encrypted)
                for uname, udata in data.items():
                    users.append(cls(uname, **udata))
            except Exception:
                current_app.logger.error("Error loading all users")
        return users

    @classmethod
    def user_exists(cls, username):
        """Check if a user exists"""
        return cls.get(username) is not None
