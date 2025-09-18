import os
import json
import uuid
from datetime import datetime
from flask import current_app
from app.utils.encryption import get_encryption_manager

class KeyManager:
    """Key management system for secure credential storage"""

    def __init__(self):
        self.keys_file = os.path.join(
            current_app.config['DATA_DIR'], 'encrypted', 'keys.enc'
        )

    def _load_keys_data(self):
        """Load and decrypt all keys data"""
        if os.path.exists(self.keys_file):
            try:
                with open(self.keys_file, 'r') as f:
                    encrypted = f.read()
                return get_encryption_manager().decrypt_data(encrypted)
            except Exception as e:
                current_app.logger.error(f"Failed to load keys data: {e}")
                return {}
        return {}

    def _save_keys_data(self, keys_data):
        """Encrypt and save all keys data"""
        encrypted = get_encryption_manager().encrypt_data(keys_data)
        os.makedirs(os.path.dirname(self.keys_file), exist_ok=True)
        with open(self.keys_file, 'w') as f:
            f.write(encrypted)

    def get_user_keys(self, username, category=None, search_term=None, tags=None):
        """
        Retrieve a user's keys with optional filtering by category,
        search term (in name/description/tags), or tags list.
        """
        keys_data = self._load_keys_data()
        user_keys = keys_data.get(username, [])
        filtered = []

        for key in user_keys:
            # Category filter
            if category and key.get('category') != category:
                continue
            # Search filter
            if search_term:
                st = search_term.lower()
                if not (
                    st in key.get('name', '').lower() or
                    st in key.get('description', '').lower() or
                    any(st in t.lower() for t in key.get('tags', []))
                ):
                    continue
            # Tags filter
            if tags:
                if not any(t in key.get('tags', []) for t in tags):
                    continue
            # Update access timestamp
            key['accessed_at'] = datetime.utcnow().isoformat()
            filtered.append(key)

        # Persist updated access times
        if filtered:
            keys_data[username] = user_keys
            self._save_keys_data(keys_data)

        return filtered

    def add_key(self, username, name, value, description="", category="", tags=None):
        """
        Add a new encrypted key or update existing key by name.
        Returns the key's UUID.
        """
        if tags is None:
            tags = []

        keys_data = self._load_keys_data()
        user_list = keys_data.setdefault(username, [])

        # Update existing key
        for i, existing in enumerate(user_list):
            if existing['name'] == name:
                existing.update({
                    'encrypted_value': get_encryption_manager().encrypt_string(value),
                    'description': description,
                    'category': category,
                    'tags': tags,
                    'updated_at': datetime.utcnow().isoformat(),
                    'accessed_at': datetime.utcnow().isoformat(),
                })
                self._save_keys_data(keys_data)
                return existing['id']

        # Create new key
        key_id = str(uuid.uuid4())
        new_key = {
            'id': key_id,
            'name': name,
            'encrypted_value': get_encryption_manager().encrypt_string(value),
            'description': description,
            'category': category,
            'tags': tags,
            'shared_with': [],
            'created_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat(),
            'accessed_at': datetime.utcnow().isoformat(),
        }
        user_list.append(new_key)
        self._save_keys_data(keys_data)
        return key_id

    def get_key_value(self, username, name):
        """
        Decrypt and return a key's value by name.
        Returns None if not found or decryption fails.
        """
        keys_data = self._load_keys_data()
        for key in keys_data.get(username, []):
            if key['name'] == name:
                try:
                    val = get_encryption_manager().decrypt_string(
                        key['encrypted_value']
                    )
                    # Update access time
                    key['accessed_at'] = datetime.utcnow().isoformat()
                    self._save_keys_data(keys_data)
                    return val
                except Exception as e:
                    current_app.logger.error(f"Decryption error for key '{name}': {e}")
                    return None
        return None

    def update_key(self, username, name, value=None, description=None,
                   category=None, tags=None):
        """
        Update fields of an existing key.
        Returns True if updated, False if not found.
        """
        keys_data = self._load_keys_data()
        for key in keys_data.get(username, []):
            if key['name'] == name:
                if value is not None:
                    key['encrypted_value'] = get_encryption_manager().encrypt_string(value)
                if description is not None:
                    key['description'] = description
                if category is not None:
                    key['category'] = category
                if tags is not None:
                    key['tags'] = tags
                key['updated_at'] = datetime.utcnow().isoformat()
                self._save_keys_data(keys_data)
                return True
        return False

    def delete_key(self, username, name):
        """
        Delete a key by name.
        Returns True if deleted, False if not found.
        """
        keys_data = self._load_keys_data()
        user_list = keys_data.get(username, [])
        filtered = [k for k in user_list if k['name'] != name]
        if len(filtered) != len(user_list):
            keys_data[username] = filtered
            self._save_keys_data(keys_data)
            return True
        return False

    def share_key(self, owner, name, target_user, permissions=None):
        """
        Share a key with another user, with specified permissions dict.
        Returns True if successful, False otherwise.
        """
        if permissions is None:
            permissions = {'read': True, 'write': False}

        keys_data = self._load_keys_data()
        for key in keys_data.get(owner, []):
            if key['name'] == name:
                # Append share entry
                key.setdefault('shared_with', []).append({
                    'username': target_user,
                    'permissions': permissions,
                    'shared_at': datetime.utcnow().isoformat()
                })
                self._save_keys_data(keys_data)
                return True
        return False

    def get_shared_keys(self, username):
        """
        Retrieve keys shared with the given username.
        """
        keys_data = self._load_keys_data()
        shared = []
        for owner, user_keys in keys_data.items():
            if owner == username:
                continue
            for key in user_keys:
                for share in key.get('shared_with', []):
                    if share['username'] == username:
                        # Return a copy with owner and permissions
                        k = key.copy()
                        k['owner'] = owner
                        k['permissions'] = share['permissions']
                        k['shared_at'] = share['shared_at']
                        shared.append(k)
        return shared

    def get_categories(self, username):
        """
        List unique categories for a user.
        """
        keys_data = self._load_keys_data()
        return sorted({k.get('category') for k in keys_data.get(username, []) if k.get('category')})

    def get_all_tags(self, username):
        """
        List unique tags for a user.
        """
        keys_data = self._load_keys_data()
        tags = set()
        for k in keys_data.get(username, []):
            tags.update(k.get('tags', []))
        return sorted(tags)

    def bulk_delete_keys(self, username, names):
        """
        Delete multiple keys. Returns count deleted.
        """
        keys_data = self._load_keys_data()
        user_list = keys_data.get(username, [])
        original = len(user_list)
        user_list = [k for k in user_list if k['name'] not in names]
        deleted = original - len(user_list)
        if deleted:
            keys_data[username] = user_list
            self._save_keys_data(keys_data)
        return deleted

    def export_keys(self, username, include_values=False):
        """
        Export keys to a list of dicts.
        If include_values=True, decrypted values are included.
        """
        keys_data = self._load_keys_data()
        exported = []
        for k in keys_data.get(username, []):
            entry = {
                'name': k['name'],
                'description': k['description'],
                'category': k['category'],
                'tags': k['tags'],
                'created_at': k['created_at'],
                'updated_at': k['updated_at']
            }
            if include_values:
                try:
                    entry['value'] = get_encryption_manager().decrypt_string(
                        k['encrypted_value']
                    )
                except:
                    entry['value'] = None
            exported.append(entry)
        return exported

    def import_keys(self, username, data, overwrite=False):
        """
        Import keys from a list of dicts.
        Returns {'imported': int, 'skipped': int}
        """
        imported = skipped = 0
        for item in data:
            name = item.get('name')
            if not overwrite and self.key_exists(username, name):
                skipped += 1
                continue
            self.add_key(
                username,
                name,
                item.get('value', ''),
                item.get('description', ''),
                item.get('category', ''),
                item.get('tags', [])
            )
            imported += 1
        return {'imported': imported, 'skipped': skipped}

    def key_exists(self, username, name):
        """Check if a key already exists for a user."""
        keys_data = self._load_keys_data()
        return any(k['name'] == name for k in keys_data.get(username, []))

# Global instance
key_manager = KeyManager()
