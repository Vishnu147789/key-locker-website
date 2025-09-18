from flask import render_template, request, redirect, url_for, flash, session, jsonify, send_file
from app.main import bp
from app.models.user import User
from app.models.key import key_manager
from app.utils.encryption import login_required, admin_required
import json
import csv
from io import StringIO, BytesIO

@bp.route('/')
@bp.route('/index')
def index():
    if 'username' in session:
        return redirect(url_for('main.dashboard'))
    return render_template('index.html', title='Home')

@bp.route('/dashboard')
@login_required
def dashboard():
    username = session['username']
    
    # Get filters from query parameters
    category = request.args.get('category', '')
    search = request.args.get('search', '')
    tags = request.args.get('tags', '').split(',') if request.args.get('tags') else None
    
    # Get user keys
    keys = key_manager.get_user_keys(username, category, search, tags)
    
    # Get categories and tags for filters
    categories = key_manager.get_categories(username)
    all_tags = key_manager.get_all_tags(username)
    
    # Get shared keys
    shared_keys = key_manager.get_shared_keys(username)
    
    return render_template('main/dashboard.html', title='Dashboard',
                         keys=keys, categories=categories, tags=all_tags,
                         shared_keys=shared_keys, current_category=category,
                         current_search=search)

@bp.route('/add-key', methods=['GET', 'POST'])
@login_required
def add_key():
    if request.method == 'POST':
        key_name = request.form.get('key_name', '').strip()
        key_value = request.form.get('key_value', '').strip()
        description = request.form.get('description', '').strip()
        category = request.form.get('category', '').strip()
        tags_str = request.form.get('tags', '').strip()
        
        # Parse tags
        tags = [tag.strip() for tag in tags_str.split(',') if tag.strip()] if tags_str else []
        
        # Validate input
        if not key_name:
            flash('Key name is required', 'danger')
            return render_template('main/add_key.html', title='Add Key',
                                 key_name=key_name, key_value=key_value,
                                 description=description, category=category,
                                 tags=tags_str)
        
        if not key_value:
            flash('Key value is required', 'danger')
            return render_template('main/add_key.html', title='Add Key',
                                 key_name=key_name, key_value=key_value,
                                 description=description, category=category,
                                 tags=tags_str)
        
        # Check if key already exists
        if key_manager.key_exists(session['username'], key_name):
            flash('A key with this name already exists', 'danger')
            return render_template('main/add_key.html', title='Add Key',
                                 key_name=key_name, key_value=key_value,
                                 description=description, category=category,
                                 tags=tags_str)
        
        # Add key
        try:
            key_id = key_manager.add_key(session['username'], key_name, key_value,
                                       description, category, tags)
            flash(f'Key "{key_name}" added successfully!', 'success')
            return redirect(url_for('main.dashboard'))
        except Exception as e:
            flash('An error occurred while adding the key', 'danger')
            return render_template('main/add_key.html', title='Add Key',
                                 key_name=key_name, key_value=key_value,
                                 description=description, category=category,
                                 tags=tags_str)
    
    # Get categories for dropdown
    categories = key_manager.get_categories(session['username'])
    tags = key_manager.get_all_tags(session['username'])
    
    return render_template('main/add_key.html', title='Add Key',
                         categories=categories, tags=tags)

@bp.route('/edit-key/<key_name>', methods=['GET', 'POST'])
@login_required
def edit_key(key_name):
    username = session['username']
    
    # Get key data
    keys = key_manager.get_user_keys(username)
    current_key = next((k for k in keys if k['name'] == key_name), None)
    
    if not current_key:
        flash('Key not found', 'danger')
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        key_value = request.form.get('key_value', '').strip()
        description = request.form.get('description', '').strip()
        category = request.form.get('category', '').strip()
        tags_str = request.form.get('tags', '').strip()
        
        # Parse tags
        tags = [tag.strip() for tag in tags_str.split(',') if tag.strip()] if tags_str else []
        
        # Validate input
        if not key_value:
            flash('Key value is required', 'danger')
            return render_template('main/edit_key.html', title='Edit Key',
                                 key=current_key, categories=key_manager.get_categories(username),
                                 tags=key_manager.get_all_tags(username))
        
        # Update key
        try:
            success = key_manager.update_key(username, key_name, key_value,
                                           description, category, tags)
            if success:
                flash(f'Key "{key_name}" updated successfully!', 'success')
                return redirect(url_for('main.dashboard'))
            else:
                flash('Key not found', 'danger')
                return redirect(url_for('main.dashboard'))
        except Exception as e:
            flash('An error occurred while updating the key', 'danger')
    
    # Get current key value for editing
    current_key['decrypted_value'] = key_manager.get_key_value(username, key_name)
    current_key['tags_str'] = ', '.join(current_key.get('tags', []))
    
    categories = key_manager.get_categories(username)
    tags = key_manager.get_all_tags(username)
    
    return render_template('main/edit_key.html', title='Edit Key',
                         key=current_key, categories=categories, tags=tags)

@bp.route('/view-key/<key_name>')
@login_required
def view_key(key_name):
    username = session['username']
    
    # Get key data
    keys = key_manager.get_user_keys(username)
    current_key = next((k for k in keys if k['name'] == key_name), None)
    
    if not current_key:
        flash('Key not found', 'danger')
        return redirect(url_for('main.dashboard'))
    
    return render_template('main/view_key.html', title='View Key',
                         key=current_key)

@bp.route('/get-key-value/<key_name>')
@login_required
def get_key_value(key_name):
    username = session['username']
    key_value = key_manager.get_key_value(username, key_name)
    
    if key_value is not None:
        return jsonify({'success': True, 'value': key_value})
    else:
        return jsonify({'success': False, 'error': 'Key not found or decryption failed'})

@bp.route('/delete-key/<key_name>')
@login_required
def delete_key(key_name):
    username = session['username']
    
    if key_manager.delete_key(username, key_name):
        flash(f'Key "{key_name}" deleted successfully!', 'success')
    else:
        flash('Key not found', 'danger')
    
    return redirect(url_for('main.dashboard'))

@bp.route('/bulk-delete-keys', methods=['POST'])
@login_required
def bulk_delete_keys():
    username = session['username']
    data = request.get_json()
    key_names = data.get('key_names', [])
    
    if not key_names:
        return jsonify({'success': False, 'error': 'No keys selected'})
    
    deleted_count = key_manager.bulk_delete_keys(username, key_names)
    
    if deleted_count > 0:
        return jsonify({'success': True, 'deleted_count': deleted_count})
    else:
        return jsonify({'success': False, 'error': 'No keys were deleted'})

@bp.route('/share-key/<key_name>', methods=['GET', 'POST'])
@login_required
def share_key(key_name):
    username = session['username']
    
    if request.method == 'POST':
        target_username = request.form.get('target_username', '').strip()
        read_permission = request.form.get('read_permission') == 'on'
        write_permission = request.form.get('write_permission') == 'on'
        
        if not target_username:
            flash('Target username is required', 'danger')
            return render_template('main/share_key.html', title='Share Key',
                                 key_name=key_name)
        
        if not User.user_exists(target_username):
            flash('Target user does not exist', 'danger')
            return render_template('main/share_key.html', title='Share Key',
                                 key_name=key_name)
        
        if target_username == username:
            flash('You cannot share a key with yourself', 'danger')
            return render_template('main/share_key.html', title='Share Key',
                                 key_name=key_name)
        
        permissions = {
            'read': read_permission,
            'write': write_permission
        }
        
        if key_manager.share_key(username, key_name, target_username, permissions):
            flash(f'Key "{key_name}" shared with {target_username} successfully!', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Failed to share key', 'danger')
    
    return render_template('main/share_key.html', title='Share Key',
                         key_name=key_name)

@bp.route('/export-keys')
@login_required
def export_keys():
    username = session['username']
    include_values = request.args.get('include_values') == 'true'
    export_format = request.args.get('format', 'json')
    
    keys = key_manager.export_keys(username, include_values)
    
    if export_format == 'csv':
        # Create CSV
        output = StringIO()
        if keys:
            fieldnames = keys[0].keys()
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(keys)
        
        # Create file response
        csv_data = output.getvalue()
        output.close()
        
        response = BytesIO()
        response.write(csv_data.encode('utf-8'))
        response.seek(0)
        
        return send_file(response, as_attachment=True,
                        download_name=f'{username}_keys_export.csv',
                        mimetype='text/csv')
    else:
        # Create JSON
        json_data = json.dumps(keys, indent=2, ensure_ascii=False)
        
        response = BytesIO()
        response.write(json_data.encode('utf-8'))
        response.seek(0)
        
        return send_file(response, as_attachment=True,
                        download_name=f'{username}_keys_export.json',
                        mimetype='application/json')

@bp.route('/import-keys', methods=['GET', 'POST'])
@login_required
def import_keys():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)
        
        overwrite = request.form.get('overwrite') == 'on'
        
        try:
            if file.filename.endswith('.json'):
                data = json.loads(file.read().decode('utf-8'))
            elif file.filename.endswith('.csv'):
                content = file.read().decode('utf-8')
                reader = csv.DictReader(StringIO(content))
                data = list(reader)
            else:
                flash('Unsupported file format. Please use JSON or CSV.', 'danger')
                return redirect(request.url)
            
            result = key_manager.import_keys(session['username'], data, overwrite)
            
            flash(f'Import completed! {result["imported"]} keys imported, '
                  f'{result["skipped"]} keys skipped.', 'success')
            return redirect(url_for('main.dashboard'))
            
        except Exception as e:
            flash(f'Error importing file: {str(e)}', 'danger')
    
    return render_template('main/import_keys.html', title='Import Keys')

@bp.route('/search-keys')
@login_required
def search_keys():
    username = session['username']
    query = request.args.get('q', '').strip()
    category = request.args.get('category', '')
    
    if not query:
        return jsonify({'success': False, 'error': 'Search query is required'})
    
    try:
        # Search keys
        keys = key_manager.get_user_keys(username, category, query)
        
        # Format results for JSON response
        results = []
        for key in keys:
            results.append({
                'name': key['name'],
                'description': key.get('description', ''),
                'category': key.get('category', ''),
                'tags': key.get('tags', []),
                'created_at': key.get('created_at'),
                'updated_at': key.get('updated_at')
            })
        
        return jsonify({
            'success': True,
            'results': results,
            'count': len(results)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@bp.route('/key-statistics')
@login_required
def key_statistics():
    username = session['username']
    
    try:
        # Get all user keys
        keys = key_manager.get_user_keys(username)
        
        # Calculate statistics
        total_keys = len(keys)
        categories = key_manager.get_categories(username)
        total_categories = len(categories)
        
        # Category distribution
        category_stats = {}
        for category in categories:
            category_keys = key_manager.get_user_keys(username, category=category)
            category_stats[category] = len(category_keys)
        
        # Recent activity (keys created in last 30 days)
        from datetime import datetime, timedelta
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_keys = [
            key for key in keys 
            if key.get('created_at') and 
            datetime.fromisoformat(key['created_at'].replace('Z', '+00:00')) > thirty_days_ago
        ]
        
        stats = {
            'total_keys': total_keys,
            'total_categories': total_categories,
            'recent_keys': len(recent_keys),
            'category_distribution': category_stats
        }
        
        return jsonify({'success': True, 'statistics': stats})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@bp.route('/generate-password')
@login_required
def generate_password():
    """Generate a secure random password"""
    import secrets
    import string
    
    # Get parameters
    length = int(request.args.get('length', 16))
    include_uppercase = request.args.get('uppercase', 'true') == 'true'
    include_lowercase = request.args.get('lowercase', 'true') == 'true'
    include_numbers = request.args.get('numbers', 'true') == 'true'
    include_symbols = request.args.get('symbols', 'true') == 'true'
    
    # Validate length
    if length < 4 or length > 128:
        return jsonify({'success': False, 'error': 'Password length must be between 4 and 128'})
    
    # Build character set
    charset = ''
    if include_lowercase:
        charset += string.ascii_lowercase
    if include_uppercase:
        charset += string.ascii_uppercase
    if include_numbers:
        charset += string.digits
    if include_symbols:
        charset += '!@#$%^&*()_+-=[]{}|;:,.<>?'
    
    if not charset:
        return jsonify({'success': False, 'error': 'At least one character type must be selected'})
    
    # Generate password
    password = ''.join(secrets.choice(charset) for _ in range(length))
    
    return jsonify({'success': True, 'password': password})

@bp.route('/recent-activity')
@login_required
def recent_activity():
    """Get recent key activity for the user"""
    username = session['username']
    
    try:
        # Get user keys with recent activity
        keys = key_manager.get_user_keys(username)
        
        # Sort by last accessed/updated time
        recent_keys = sorted(
            keys,
            key=lambda x: x.get('accessed_at', x.get('updated_at', x.get('created_at', ''))),
            reverse=True
        )[:10]  # Get last 10 activities
        
        activities = []
        for key in recent_keys:
            activity = {
                'key_name': key['name'],
                'action': 'accessed' if key.get('accessed_at') else 'updated',
                'timestamp': key.get('accessed_at', key.get('updated_at', key.get('created_at'))),
                'category': key.get('category', 'Uncategorized')
            }
            activities.append(activity)
        
        return jsonify({'success': True, 'activities': activities})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
