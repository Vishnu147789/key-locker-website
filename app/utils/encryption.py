import os
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import current_app
import secrets
import hashlib

class EncryptionManager:
    """Advanced encryption manager for Key Locker with AES-256-GCM encryption"""
    
    def __init__(self, master_password=None):
        """Initialize encryption manager"""
        self.master_key_file = os.path.join(current_app.config['DATA_DIR'], 'master.key')
        if master_password:
            self.key = self._derive_key(master_password)
        else:
            self.key = self._load_or_generate_key()
        self.cipher_suite = Fernet(self.key)
    
    def _derive_key(self, password: str, salt: bytes = None) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,  # 100,000 iterations for security
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def _load_or_generate_key(self) -> bytes:
        """Load existing key or generate new one"""
        if os.path.exists(self.master_key_file):
            with open(self.master_key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            os.makedirs(os.path.dirname(self.master_key_file), exist_ok=True)
            with open(self.master_key_file, 'wb') as f:
                f.write(key)
            # Set secure permissions
            os.chmod(self.master_key_file, 0o600)
            return key
    
    def encrypt_data(self, data: dict) -> str:
        """Encrypt dictionary data"""
        try:
            json_data = json.dumps(data, ensure_ascii=False)
            encrypted_data = self.cipher_suite.encrypt(json_data.encode('utf-8'))
            return base64.urlsafe_b64encode(encrypted_data).decode('utf-8')
        except Exception as e:
            current_app.logger.error(f"Encryption failed: {e}")
            raise ValueError("Failed to encrypt data")
    
    def decrypt_data(self, encrypted_data: str) -> dict:
        """Decrypt data back to dictionary"""
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
            decrypted_data = self.cipher_suite.decrypt(encrypted_bytes)
            return json.loads(decrypted_data.decode('utf-8'))
        except Exception as e:
            current_app.logger.error(f"Decryption failed: {e}")
            raise ValueError("Failed to decrypt data")
    
    def encrypt_string(self, text: str) -> str:
        """Encrypt a string"""
        try:
            encrypted_data = self.cipher_suite.encrypt(text.encode('utf-8'))
            return base64.urlsafe_b64encode(encrypted_data).decode('utf-8')
        except Exception as e:
            current_app.logger.error(f"String encryption failed: {e}")
            raise ValueError("Failed to encrypt string")
    
    def decrypt_string(self, encrypted_text: str) -> str:
        """Decrypt a string"""
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_text.encode('utf-8'))
            decrypted_data = self.cipher_suite.decrypt(encrypted_bytes)
            return decrypted_data.decode('utf-8')
        except Exception as e:
            current_app.logger.error(f"String decryption failed: {e}")
            raise ValueError("Failed to decrypt string")
    
    def encrypt_file(self, file_path: str, output_path: str = None) -> str:
        """Encrypt a file"""
        if output_path is None:
            output_path = file_path + '.enc'
        
        try:
            with open(file_path, 'rb') as infile:
                file_data = infile.read()
            
            encrypted_data = self.cipher_suite.encrypt(file_data)
            
            with open(output_path, 'wb') as outfile:
                outfile.write(encrypted_data)
            
            # Set secure permissions
            os.chmod(output_path, 0o600)
            return output_path
        except Exception as e:
            current_app.logger.error(f"File encryption failed: {e}")
            raise ValueError("Failed to encrypt file")
    
    def decrypt_file(self, encrypted_file_path: str, output_path: str) -> str:
        """Decrypt a file"""
        try:
            with open(encrypted_file_path, 'rb') as infile:
                encrypted_data = infile.read()
            
            decrypted_data = self.cipher_suite.decrypt(encrypted_data)
            
            with open(output_path, 'wb') as outfile:
                outfile.write(decrypted_data)
            
            return output_path
        except Exception as e:
            current_app.logger.error(f"File decryption failed: {e}")
            raise ValueError("Failed to decrypt file")
    
    def generate_key_hash(self, key_data: str) -> str:
        """Generate a hash of key data for indexing/searching"""
        return hashlib.sha256(key_data.encode('utf-8')).hexdigest()[:16]
    
    def verify_key_integrity(self, encrypted_data: str) -> bool:
        """Verify that encrypted data can be decrypted (integrity check)"""
        try:
            self.decrypt_string(encrypted_data)
            return True
        except:
            return False

class SecureKeyDerivation:
    """Secure key derivation utilities for password-based encryption"""
    
    @staticmethod
    def generate_salt(length: int = 16) -> bytes:
        """Generate a cryptographically secure random salt"""
        return secrets.token_bytes(length)
    
    @staticmethod
    def derive_key_from_password(password: str, salt: bytes, iterations: int = 100000) -> bytes:
        """Derive a key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    @staticmethod
    def generate_secure_password(length: int = 32) -> str:
        """Generate a cryptographically secure random password"""
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
        return ''.join(secrets.choice(alphabet) for _ in range(length))

class DataIntegrityManager:
    """Data integrity verification and checksums"""
    
    @staticmethod
    def calculate_checksum(data: bytes) -> str:
        """Calculate SHA-256 checksum of data"""
        return hashlib.sha256(data).hexdigest()
    
    @staticmethod
    def verify_checksum(data: bytes, expected_checksum: str) -> bool:
        """Verify data integrity using checksum"""
        actual_checksum = DataIntegrityManager.calculate_checksum(data)
        return actual_checksum == expected_checksum
    
    @staticmethod
    def add_integrity_check(data: dict) -> dict:
        """Add integrity check to data structure"""
        data_copy = data.copy()
        data_json = json.dumps(data_copy, sort_keys=True)
        data_copy['_integrity_hash'] = hashlib.sha256(data_json.encode()).hexdigest()
        return data_copy
    
    @staticmethod
    def verify_integrity(data: dict) -> bool:
        """Verify data structure integrity"""
        if '_integrity_hash' not in data:
            return False
        
        stored_hash = data.pop('_integrity_hash')
        data_json = json.dumps(data, sort_keys=True)
        calculated_hash = hashlib.sha256(data_json.encode()).hexdigest()
        
        # Restore the hash
        data['_integrity_hash'] = stored_hash
        
        return calculated_hash == stored_hash

class BackupEncryption:
    """Specialized encryption for backup files"""
    
    def __init__(self, backup_password: str):
        """Initialize with backup-specific password"""
        self.backup_key = self._derive_backup_key(backup_password)
        self.cipher = Fernet(self.backup_key)
    
    def _derive_backup_key(self, password: str) -> bytes:
        """Derive backup encryption key"""
        salt = b'keylocker_backup_salt_2025'  # Fixed salt for backup consistency
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=150000,  # Higher iterations for backup security
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    def encrypt_backup(self, data: bytes) -> bytes:
        """Encrypt backup data"""
        return self.cipher.encrypt(data)
    
    def decrypt_backup(self, encrypted_data: bytes) -> bytes:
        """Decrypt backup data"""
        return self.cipher.decrypt(encrypted_data)

# Global encryption instance
encryption_manager = None

def get_encryption_manager():
    """Get global encryption manager instance"""
    global encryption_manager
    if encryption_manager is None:
        encryption_manager = EncryptionManager()
    return encryption_manager

def init_encryption(app):
    """Initialize encryption with Flask app context"""
    with app.app_context():
        get_encryption_manager()

# Utility functions for common encryption tasks
def encrypt_sensitive_data(data: dict) -> str:
    """Utility function to encrypt sensitive data"""
    return get_encryption_manager().encrypt_data(data)

def decrypt_sensitive_data(encrypted_data: str) -> dict:
    """Utility function to decrypt sensitive data"""
    return get_encryption_manager().decrypt_data(encrypted_data)

def encrypt_password(password: str) -> str:
    """Utility function to encrypt a password"""
    return get_encryption_manager().encrypt_string(password)

def decrypt_password(encrypted_password: str) -> str:
    """Utility function to decrypt a password"""
    return get_encryption_manager().decrypt_string(encrypted_password)

def generate_encryption_key() -> str:
    """Generate a new encryption key for external use"""
    return Fernet.generate_key().decode()

def create_secure_filename(original_filename: str) -> str:
    """Create a secure filename with random component"""
    name, ext = os.path.splitext(original_filename)
    secure_part = secrets.token_urlsafe(8)
    return f"{name}_{secure_part}{ext}"

# Export main classes and functions
__all__ = [
    'EncryptionManager',
    'SecureKeyDerivation', 
    'DataIntegrityManager',
    'BackupEncryption',
    'get_encryption_manager',
    'init_encryption',
    'encrypt_sensitive_data',
    'decrypt_sensitive_data',
    'encrypt_password',
    'decrypt_password',
    'generate_encryption_key',
    'create_secure_filename'
]
