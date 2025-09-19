import os
from datetime import timedelta

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    # App metadata
    APP_NAME = os.environ.get('APP_NAME', 'Key Locker')
    APP_VERSION = os.environ.get('APP_VERSION', '1.0.0')
    APP_DESCRIPTION = 'Secure credential management and key storage'

    # Flask core settings
    SECRET_KEY = os.environ.get('SECRET_KEY', 'replace-this-in-production')
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)

    # Data directories
    DATA_DIR = os.environ.get('DATA_DIR', os.path.join(basedir, '../data'))
    BACKUP_DIR = os.environ.get('BACKUP_DIR', os.path.join(basedir, '../backups'))
    LOG_DIR = os.environ.get('LOG_DIR', os.path.join(basedir, '../logs'))

    # Security settings
    MAX_LOGIN_ATTEMPTS = int(os.environ.get('MAX_LOGIN_ATTEMPTS', 5))
    LOCKOUT_DURATION = int(os.environ.get('LOCKOUT_DURATION', 900))  # in seconds
    PASSWORD_MIN_LENGTH = int(os.environ.get('PASSWORD_MIN_LENGTH', 8))
    REQUIRE_UPPERCASE = os.environ.get('REQUIRE_UPPERCASE', 'True').lower() == 'true'
    REQUIRE_LOWERCASE = os.environ.get('REQUIRE_LOWERCASE', 'True').lower() == 'true'
    REQUIRE_NUMBERS = os.environ.get('REQUIRE_NUMBERS', 'True').lower() == 'true'
    REQUIRE_SPECIAL_CHARS = os.environ.get('REQUIRE_SPECIAL_CHARS', 'True').lower() == 'true'

    # Crypto/Encryption settings
    ENCRYPTION_ALGORITHM = 'AES-256-GCM'
    MASTER_KEY_FILE = os.path.join(DATA_DIR, 'master.key')
    KEY_DERIVATION_ROUNDS = int(os.environ.get('KEY_DERIVATION_ROUNDS', 100000))

    # Two-factor authentication
    TWO_FA_ISSUER_NAME = os.environ.get('TWO_FA_ISSUER_NAME', APP_NAME)
    TWO_FA_WINDOW = int(os.environ.get('TWO_FA_WINDOW', 1))

    # File uploads
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024))  # 16MB
    UPLOAD_FOLDER = os.path.join(DATA_DIR, 'uploads')
    ALLOWED_EXTENSIONS = {'json', 'csv', 'txt'}

    # Logging and audit
    AUDIT_LOG_ENABLED = True
    AUDIT_LOG_FILE = os.path.join(LOG_DIR, 'audit.log')
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FORMAT = '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'

    # Admin roles
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', '')
    SEND_SECURITY_ALERTS = os.environ.get('SEND_SECURITY_ALERTS', 'False').lower() == 'true'

    # Other feature flags
    FEATURES = {
        'TWO_FACTOR_AUTH': True,
        'IP_WHITELISTING': True,
        'AUDIT_LOGGING': True,
        'BACKUP_ENCRYPTION': True,
        'IMPORT_EXPORT': True,
        'KEY_SHARING': True
    }

    # Default key categories
    DEFAULT_KEY_CATEGORIES = [
        'API Keys', 'Database Credentials', 'SSH Keys', 'SSL Certificates', 
        'Service Accounts', 'Personal Accounts', 'Development', 
        'Production', 'Testing', 'Backup Codes'
    ]

    @staticmethod
    def init_app(app):
        os.makedirs(Config.DATA_DIR, exist_ok=True)
        os.makedirs(Config.BACKUP_DIR, exist_ok=True)
        os.makedirs(Config.LOG_DIR, exist_ok=True)
        os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
        os.makedirs(os.path.join(Config.DATA_DIR, 'encrypted'), exist_ok=True)
        # Set secure permissions
        os.chmod(Config.DATA_DIR, 0o700)
        os.chmod(os.path.join(Config.DATA_DIR, 'encrypted'), 0o700)

class DevelopmentConfig(Config):
    DEBUG = True
    ENV = 'development'
    LOG_LEVEL = 'DEBUG'

class ProductionConfig(Config):
    DEBUG = False
    ENV = 'production'
    SESSION_COOKIE_SECURE = True
    LOG_LEVEL = 'WARNING'

class TestingConfig(Config):
    TESTING = True
    ENV = 'testing'
    WTF_CSRF_ENABLED = False
    DATA_DIR = os.path.join(basedir, '../test_data')

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

def get_config(config_name=None):
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'default')
    return config.get(config_name, config['default'])
