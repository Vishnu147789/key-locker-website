// Dashboard specific scripts - filtering, sorting, search, bulk actions

document.addEventListener('DOMContentLoaded', () => {
  const searchInput = document.getElementById('searchInput');
  const categoryFilter = document.getElementById('categoryFilter');
  const clearSearchBtn = document.getElementById('clearSearch');
  const bulkDeleteBtn = document.getElementById('bulkDeleteBtn');
  let selectedKeys = new Set();

  // Search and filter keys
  function filterKeys() {
    const searchTerm = searchInput.value.toLowerCase();
    const category = categoryFilter.value;
    const keys = document.querySelectorAll('.key-card');
    let visibleCount = 0;

    keys.forEach(card => {
      const name = card.dataset.name.toLowerCase();
      const description = card.dataset.description?.toLowerCase() || '';
      const tags = card.dataset.tags?.toLowerCase() || '';
      const cardCategory = card.dataset.category || '';

      // Filter logic
      const matchesSearch = name.includes(searchTerm) || description.includes(searchTerm) || tags.includes(searchTerm);
      const matchesCategory = !category || cardCategory === category;

      if (matchesSearch && matchesCategory) {
        card.style.display = '';
        visibleCount++;
      } else {
        card.style.display = 'none';
      }
    });

    document.getElementById('keyCount').textContent = `${visibleCount} keys found`;

    toggleClearSearchButton();
    updateBulkDeleteButton();
  }

  // Clear search input
  function clearSearch() {
    searchInput.value = '';
    filterKeys();
  }

  // Toggle clear search button visibility
  function toggleClearSearchButton() {
    const btn = clearSearchBtn;
    btn.style.display = searchInput.value ? 'inline-block' : 'none';
  }

  // Handle checkbox selection for bulk actions
  function toggleKeySelection(event) {
    const checkbox = event.target;
    const keyName = checkbox.value;

    if (checkbox.checked) {
      selectedKeys.add(keyName);
    } else {
      selectedKeys.delete(keyName);
    }

    updateBulkDeleteButton();
  }

  // Enable or disable bulk delete button
  function updateBulkDeleteButton() {
    bulkDeleteBtn.disabled = selectedKeys.size === 0;
    bulkDeleteBtn.textContent = selectedKeys.size ? `Delete Selected (${selectedKeys.size})` : 'Delete Selected';
  }

  // Select or deselect all checkboxes
  function toggleSelectAll() {
    const checkboxes = document.querySelectorAll('.key-checkbox');
    const allSelected = [...checkboxes].every(cb => cb.checked);

    checkboxes.forEach(cb => {
      cb.checked = !allSelected;
      if (cb.checked) selectedKeys.add(cb.value);
      else selectedKeys.delete(cb.value);
    });

    updateBulkDeleteButton();
  }

  // Bulk delete keys
  async function bulkDelete() {
    if (!confirm(`Delete ${selectedKeys.size} keys? This cannot be undone.`)) return;

    const response = await fetch('/bulk-delete-keys', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key_names: Array.from(selectedKeys) }),
    });

    const result = await response.json();
    if (result.success) {
      alert(`Deleted ${result.deleted_count} keys successfully`);
      location.reload();
    } else {
      alert(`Failed to delete keys: ${result.error}`);
    }
  }

  // Attach event listeners
  searchInput.addEventListener('input', filterKeys);
  clearSearchBtn.addEventListener('click', clearSearch);
  categoryFilter.addEventListener('change', filterKeys);
  bulkDeleteBtn.addEventListener('click', bulkDelete);
  document.getElementById('selectAllBtn').addEventListener('click', toggleSelectAll);
  document.querySelectorAll('.key-checkbox').forEach(cb => cb.addEventListener('change', toggleKeySelection));

  // Initial setup
  toggleClearSearchButton();
  filterKeys();
  updateBulkDeleteButton();
});
