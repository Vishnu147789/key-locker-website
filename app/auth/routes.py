from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash
from app.utils.encryption import login_required, generate_csrf_token
from app.models.user import User
import re

bp = Blueprint('auth', __name__)

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        errors = []

        # Username validation
        if not username:
            errors.append('Username is required')
        elif len(username) < 3 or len(username) > 50:
            errors.append('Username must be between 3 and 50 characters')
        elif not re.match(r'^[a-zA-Z0-9_.-]+$', username):
            errors.append('Username can only contain letters, numbers, ., _, -')
        elif User.user_exists(username):
            errors.append('Username already exists')

        # Email validation
        if not email:
            errors.append('Email is required')
        elif not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
            errors.append('Invalid email format')

        # Password validation
        if not password:
            errors.append('Password is required')
        elif len(password) < 8:
            errors.append('Password must be at least 8 characters')
        elif password != confirm_password:
            errors.append('Passwords do not match')

        if errors:
            for err in errors:
                flash(err, 'danger')
            return render_template('auth/register.html', title='Register',
                                   username=username, email=email)

        # Create user
        user = User(username=username, email=email)
        user.set_password(password)
        user.save()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html', title='Register')


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash('Username and password are required', 'danger')
            return render_template('auth/login.html', title='Login')

        user = User.get(username)
        if not user or not user.check_password(password):
            flash('Invalid username or password', 'danger')
            return render_template('auth/login.html', title='Login')

        if user.is_account_locked():
            flash('Account is locked. Try again later.', 'danger')
            return render_template('auth/login.html', title='Login')

        session.clear()
        session['username'] = user.username
        session['role'] = user.role
        session['csrf_token'] = generate_csrf_token()

        flash(f'Welcome, {user.username}!', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('auth/login.html', title='Login')


@bp.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


@bp.route('/setup-2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    user = User.get(session['username'])

    if request.method == 'POST':
        token = request.form.get('totp_token', '').strip()
        if user.verify_totp(token):
            user.enable_two_factor()
            flash('Two-factor authentication enabled.', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Invalid 2FA code.', 'danger')

    if user.two_fa_enabled:
        flash('2FA already enabled.', 'info')
        return redirect(url_for('main.dashboard'))

    qr_data = user.setup_two_factor()
    return render_template('auth/setup_2fa.html', title='Setup 2FA',
                           qr_code=qr_data['qr_code'], secret=qr_data['secret'])


@bp.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    username = session.get('username')
    token = request.form.get('totp_token', '').strip()
    user = User.get(username)

    if not user or not user.verify_totp(token):
        flash('Invalid 2FA code.', 'danger')
        return render_template('auth/verify_2fa.html', title='Verify 2FA')

    flash('Two-factor authentication verified.', 'success')
    return redirect(url_for('main.dashboard'))


@bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    user = User.get(session['username'])

    if request.method == 'POST':
        current = request.form.get('current_password', '')
        new = request.form.get('new_password', '')
        confirm = request.form.get('confirm_password', '')

        if not user.check_password(current):
            flash('Current password incorrect.', 'danger')
            return render_template('auth/change_password.html', title='Change Password')

        if new != confirm:
            flash('Passwords do not match.', 'danger')
            return render_template('auth/change_password.html', title='Change Password')

        user.set_password(new)
        user.save()
        flash('Password changed successfully.', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('auth/change_password.html', title='Change Password')
