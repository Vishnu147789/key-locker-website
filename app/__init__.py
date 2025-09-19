import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from flask import Flask, render_template, request

def create_app(config_name=None):
    """Application factory pattern for creating Flask app instances"""
    from config import get_config

    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')

    # Create Flask application instance
    app = Flask(__name__)

    # Load configuration
    app.config.from_object(get_config(config_name))
    get_config(config_name).init_app(app)

    # Ensure required directories exist
    create_directories(app)

    # Configure logging
    configure_logging(app)

    # Register blueprints
    register_blueprints(app)

    # Register error handlers
    register_error_handlers(app)

    # Add template context processors
    register_context_processors(app)

    # Add security headers
    add_security_headers(app)

    # Register health check
    register_health_check(app)

    return app

def create_directories(app):
    """Create necessary directories for data storage"""
    directories = [
        app.config['DATA_DIR'],
        app.config['BACKUP_DIR'],
        app.config['LOG_DIR'],
        os.path.join(app.config['DATA_DIR'], 'encrypted'),
        os.path.join(app.config['DATA_DIR'], 'temp')
    ]

    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
            # Set secure permissions for data directory
            if 'data' in directory.lower():
                os.chmod(directory, 0o700)
        except OSError as e:
            if hasattr(app, 'logger'):
                app.logger.error(f"Failed to create directory {directory}: {e}")
            else:
                print(f"Failed to create directory {directory}: {e}")

def configure_logging(app):
    """Configure application logging"""
    if not app.debug and not app.testing:
        # Create logs directory if it doesn't exist
        if not os.path.exists(app.config['LOG_DIR']):
            os.makedirs(app.config['LOG_DIR'])

        # Set up file handler with rotation
        log_file = os.path.join(app.config['LOG_DIR'], 'keylocker.log')
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10240000,  # 10MB
            backupCount=10
        )

        # Set log format
        formatter = logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.INFO)

        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('Key Locker startup')

def register_blueprints(app):
    """Register application blueprints"""
    # Import blueprints
    from app.auth import bp as auth_bp
    from app.main import bp as main_bp
    from app.admin import bp as admin_bp

    # Register blueprints with URL prefixes
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp, url_prefix='/admin')

def register_error_handlers(app):
    """Register custom error handlers"""

    @app.errorhandler(400)
    def bad_request_error(error):
        return render_template('errors/400.html'), 400

    @app.errorhandler(403)
    def forbidden_error(error):
        return render_template('errors/403.html'), 403

    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('errors/404.html'), 404

    @app.errorhandler(413)
    def request_entity_too_large_error(error):
        return render_template('errors/413.html'), 413

    @app.errorhandler(500)
    def internal_error(error):
        # Log the error
        app.logger.error(f'Server Error: {error}, route: {request.url}')
        return render_template('errors/500.html'), 500

    @app.errorhandler(503)
    def service_unavailable_error(error):
        return render_template('errors/503.html'), 503

def register_context_processors(app):
    """Register template context processors"""

    @app.context_processor
    def inject_config():
        """Make config available in templates"""
        return {
            'config': app.config,
            'app_name': app.config.get('APP_NAME', 'Key Locker'),
            'app_version': app.config.get('APP_VERSION', '1.0.0')
        }

    @app.context_processor
    def inject_now():
        """Make current datetime available in templates"""
        return {'now': datetime.utcnow()}

def add_security_headers(app):
    """Add security headers to all responses"""

    @app.after_request
    def set_security_headers(response):
        # Prevent clickjacking
        response.headers['X-Frame-Options'] = 'DENY'

        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'

        # Enable XSS filtering
        response.headers['X-XSS-Protection'] = '1; mode=block'

        # Force HTTPS in production
        if app.config.get('SESSION_COOKIE_SECURE', False):
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

        # Content Security Policy
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://code.jquery.com https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "font-src 'self' https://cdnjs.cloudflare.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self';"
        )

        return response

def register_health_check(app):
    """Register health check endpoint for monitoring"""

    @app.route('/health')
    def health_check():
        """Health check endpoint for load balancers and monitoring"""
        try:
            # Check if data directory is accessible
            data_dir = app.config['DATA_DIR']
            if not os.path.exists(data_dir):
                return {'status': 'unhealthy', 'reason': 'data directory not accessible'}, 503

            # Check if we can write to temp directory
            temp_dir = os.path.join(data_dir, 'temp')
            test_file = os.path.join(temp_dir, 'health_check.tmp')
            try:
                with open(test_file, 'w') as f:
                    f.write('health check')
                os.remove(test_file)
            except:
                return {'status': 'unhealthy', 'reason': 'cannot write to temp directory'}, 503

            return {
                'status': 'healthy',
                'timestamp': str(datetime.utcnow()),
                'version': app.config.get('APP_VERSION', '1.0.0'),
                'environment': app.config.get('ENV', 'unknown')
            }
        except Exception as e:
            app.logger.error(f'Health check failed: {e}')
            return {'status': 'unhealthy', 'reason': str(e)}, 503

    @app.route('/version')
    def version_info():
        """Version information endpoint"""
        return {
            'name': app.config.get('APP_NAME', 'Key Locker'),
            'version': app.config.get('APP_VERSION', '1.0.0'),
            'environment': app.config.get('ENV', 'development'),
            'debug': app.debug
        }
