// Key management specific functionality

class KeyManager {
  constructor() {
    this.selectedKeys = new Set();
    this.init();
  }

  init() {
    this.bindEvents();
    this.setupKeyPreview();
    this.setupAutoSave();
  }

  bindEvents() {
    // Key selection
    document.querySelectorAll('.key-checkbox').forEach(checkbox => {
      checkbox.addEventListener('change', (e) => this.handleKeySelection(e));
    });

    // Bulk actions
    document.getElementById('selectAllKeys')?.addEventListener('click', () => this.selectAllKeys());
    document.getElementById('bulkDelete')?.addEventListener('click', () => this.bulkDeleteKeys());
    document.getElementById('bulkExport')?.addEventListener('click', () => this.bulkExportKeys());

    // Key actions
    document.querySelectorAll('.copy-key-btn').forEach(btn => {
      btn.addEventListener('click', (e) => this.copyKeyValue(e));
    });

    document.querySelectorAll('.share-key-btn').forEach(btn => {
      btn.addEventListener('click', (e) => this.shareKey(e));
    });

    // Search and filter
    const searchInput = document.getElementById('keySearch');
    if (searchInput) {
      searchInput.addEventListener('input', debounce(() => this.filterKeys(), 300));
    }

    const categoryFilter = document.getElementById('categoryFilter');
    if (categoryFilter) {
      categoryFilter.addEventListener('change', () => this.filterKeys());
    }
  }

  handleKeySelection(event) {
    const checkbox = event.target;
    const keyName = checkbox.value;

    if (checkbox.checked) {
      this.selectedKeys.add(keyName);
    } else {
      this.selectedKeys.delete(keyName);
    }

    this.updateBulkActionButtons();
  }

  selectAllKeys() {
    const checkboxes = document.querySelectorAll('.key-checkbox:not([disabled])');
    const allSelected = Array.from(checkboxes).every(cb => cb.checked);

    checkboxes.forEach(checkbox => {
      checkbox.checked = !allSelected;
      if (checkbox.checked) {
        this.selectedKeys.add(checkbox.value);
      } else {
        this.selectedKeys.delete(checkbox.value);
      }
    });

    this.updateBulkActionButtons();
  }

  updateBulkActionButtons() {
    const count = this.selectedKeys.size;
    const bulkActions = document.getElementById('bulkActions');
    const countDisplay = document.getElementById('selectedCount');

    if (bulkActions) {
      bulkActions.style.display = count > 0 ? 'block' : 'none';
    }
    
    if (countDisplay) {
      countDisplay.textContent = count;
    }

    // Enable/disable bulk action buttons
    document.querySelectorAll('.bulk-action-btn').forEach(btn => {
      btn.disabled = count === 0;
    });
  }

  async copyKeyValue(event) {
    const keyName = event.target.dataset.keyName;
    
    try {
      const response = await fetch(`/api/keys/${encodeURIComponent(keyName)}/value`);
      const data = await response.json();
      
      if (data.success) {
        await navigator.clipboard.writeText(data.value);
        showToast(`Key "${keyName}" copied to clipboard`, 'success');
      } else {
        showToast(data.error || 'Failed to copy key', 'error');
      }
    } catch (error) {
      console.error('Copy failed:', error);
      showToast('Failed to copy key', 'error');
    }
  }

  async bulkDeleteKeys() {
    if (this.selectedKeys.size === 0) return;

    const confirmed = confirm(
      `Are you sure you want to delete ${this.selectedKeys.size} selected keys? This cannot be undone.`
    );

    if (!confirmed) return;

    try {
      const response = await fetch('/api/keys/bulk-delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ keys: Array.from(this.selectedKeys) })
      });

      const data = await response.json();
      
      if (data.success) {
        showToast(`Successfully deleted ${data.deleted_count} keys`, 'success');
        location.reload();
      } else {
        showToast(data.error || 'Failed to delete keys', 'error');
      }
    } catch (error) {
      console.error('Bulk delete failed:', error);
      showToast('Failed to delete keys', 'error');
    }
  }

  async bulkExportKeys() {
    if (this.selectedKeys.size === 0) return;

    try {
      const response = await fetch('/api/keys/bulk-export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ keys: Array.from(this.selectedKeys) })
      });

      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `keys-export-${new Date().toISOString().split('T')[0]}.json`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        
        showToast(`Exported ${this.selectedKeys.size} keys`, 'success');
      } else {
        throw new Error('Export failed');
      }
    } catch (error) {
      console.error('Bulk export failed:', error);
      showToast('Failed to export keys', 'error');
    }
  }

  filterKeys() {
    const searchTerm = document.getElementById('keySearch')?.value.toLowerCase() || '';
    const category = document.getElementById('categoryFilter')?.value || '';
    
    const keyCards = document.querySelectorAll('.key-card');
    let visibleCount = 0;

    keyCards.forEach(card => {
      const name = card.dataset.name?.toLowerCase() || '';
      const description = card.dataset.description?.toLowerCase() || '';
      const tags = card.dataset.tags?.toLowerCase() || '';
      const keyCategory = card.dataset.category || '';

      const matchesSearch = !searchTerm || 
        name.includes(searchTerm) || 
        description.includes(searchTerm) || 
        tags.includes(searchTerm);

      const matchesCategory = !category || keyCategory === category;

      if (matchesSearch && matchesCategory) {
        card.style.display = '';
        card.classList.add('fade-in');
        visibleCount++;
      } else {
        card.style.display = 'none';
        card.classList.remove('fade-in');
      }
    });

    // Update results count
    const countElement = document.getElementById('filteredCount');
    if (countElement) {
      countElement.textContent = visibleCount;
    }

    // Show/hide empty state
    const emptyState = document.getElementById('emptyState');
    if (emptyState) {
      emptyState.style.display = visibleCount === 0 ? 'block' : 'none';
    }
  }

  setupKeyPreview() {
    document.querySelectorAll('.key-preview-btn').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        const keyName = e.target.dataset.keyName;
        const previewElement = document.getElementById(`preview-${keyName}`);
        
        if (previewElement.textContent === '••••••••') {
          try {
            const response = await fetch(`/api/keys/${encodeURIComponent(keyName)}/value`);
            const data = await response.json();
            
            if (data.success) {
              previewElement.textContent = data.value.substring(0, 20) + '...';
              e.target.innerHTML = '<i class="fas fa-eye-slash"></i>';
            }
          } catch (error) {
            console.error('Preview failed:', error);
          }
        } else {
          previewElement.textContent = '••••••••';
          e.target.innerHTML = '<i class="fas fa-eye"></i>';
        }
      });
    });
  }

  setupAutoSave() {
    const form = document.getElementById('keyForm');
    if (!form) return;

    const inputs = form.querySelectorAll('input, textarea, select');
    
    inputs.forEach(input => {
      input.addEventListener('input', debounce(() => {
        const formData = new FormData(form);
        const data = Object.fromEntries(formData);
        
        localStorage.setItem('keyFormDraft', JSON.stringify(data));
        this.showAutoSaveIndicator();
      }, 1000));
    });

    // Load draft on page load
    this.loadFormDraft();
  }

  loadFormDraft() {
    const draft = localStorage.getItem('keyFormDraft');
    if (!draft) return;

    try {
      const data = JSON.parse(draft);
      const form = document.getElementById('keyForm');
      
      Object.keys(data).forEach(key => {
        const input = form.querySelector(`[name="${key}"]`);
        if (input && input.value === '') {
          input.value = data[key];
        }
      });
    } catch (error) {
      console.error('Failed to load draft:', error);
    }
  }

  showAutoSaveIndicator() {
    let indicator = document.getElementById('autoSaveIndicator');
    
    if (!indicator) {
      indicator = document.createElement('div');
      indicator.id = 'autoSaveIndicator';
      indicator.className = 'auto-save-indicator';
      document.body.appendChild(indicator);
    }

    indicator.textContent = 'Draft saved';
    indicator.style.display = 'block';
    
    setTimeout(() => {
      indicator.style.display = 'none';
    }, 2000);
  }
}

// Initialize key manager when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  if (document.querySelector('.key-management-page')) {
    window.keyManager = new KeyManager();
  }
});
