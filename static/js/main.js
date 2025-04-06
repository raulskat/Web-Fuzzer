/**
 * Web Fuzzer - Main JavaScript File
 * Handles form validation, AJAX requests, and dynamic UI elements
 */

document.addEventListener('DOMContentLoaded', function() {
    // Form validation for all fuzzing forms
    setupFormValidation();
    
    // Setup result filtering and search
    setupResultsFiltering();
    
    // Setup dynamic loading of results
    setupResultsLoading();
    
    // Setup update functionality for URL data
    setupUrlDataUpdates();
});

/**
 * Set up form validation for all fuzzing forms
 */
function setupFormValidation() {
    const fuzzingForms = document.querySelectorAll('.fuzzing-form');
    
    fuzzingForms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const targetUrl = form.querySelector('input[name="target_url"]');
            
            if (!targetUrl || !targetUrl.value.trim()) {
                e.preventDefault();
                showAlert('Please enter a valid target URL', 'danger');
                return false;
            }
            
            // Validate URL format
            if (!isValidUrl(targetUrl.value)) {
                e.preventDefault();
                showAlert('Please enter a valid URL format (e.g., https://example.com)', 'danger');
                return false;
            }
            
            // Show loading indicator
            showLoading();
            
            // Continue with form submission
            return true;
        });
    });
}

/**
 * Validate URL format
 * @param {string} url - The URL to validate
 * @returns {boolean} - True if valid, false otherwise
 */
function isValidUrl(url) {
    try {
        new URL(url);
        return true;
    } catch (e) {
        return false;
    }
}

/**
 * Display alert message
 * @param {string} message - The message to display
 * @param {string} type - The type of alert (success, danger, warning, info)
 */
function showAlert(message, type = 'info') {
    const alertContainer = document.querySelector('.alert-container') || createAlertContainer();
    
    const alert = document.createElement('div');
    alert.className = `alert alert-${type} alert-dismissible fade show`;
    alert.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    
    alertContainer.appendChild(alert);
    
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
        if (alert && alert.parentNode) {
            alert.classList.remove('show');
            setTimeout(() => alert.remove(), 300);
        }
    }, 5000);
}

/**
 * Create alert container if it doesn't exist
 * @returns {HTMLElement} - The alert container element
 */
function createAlertContainer() {
    const container = document.createElement('div');
    container.className = 'alert-container position-fixed top-0 end-0 p-3';
    container.style.zIndex = '1050';
    document.body.appendChild(container);
    return container;
}

/**
 * Show loading indicator
 */
function showLoading() {
    const loadingEl = document.createElement('div');
    loadingEl.id = 'loading-indicator';
    loadingEl.className = 'position-fixed top-0 start-0 w-100 h-100 d-flex justify-content-center align-items-center';
    loadingEl.style.backgroundColor = 'rgba(0, 0, 0, 0.5)';
    loadingEl.style.zIndex = '2000';
    
    loadingEl.innerHTML = `
        <div class="spinner-border text-light" role="status">
            <span class="visually-hidden">Loading...</span>
        </div>
    `;
    
    document.body.appendChild(loadingEl);
}

/**
 * Hide loading indicator
 */
function hideLoading() {
    const loadingEl = document.getElementById('loading-indicator');
    if (loadingEl) {
        loadingEl.remove();
    }
}

/**
 * Set up result filtering and search functionality\r
 */\r
function setupResultsFiltering() {\r
    // Search functionality\r
    const searchInput = document.getElementById('search-results');\r
    if (searchInput) {\r
        searchInput.addEventListener('input', function() {\r
            filterResults();\r
        });\r
    }\r
    \r
    // Apply filters button\r
    const applyFiltersBtn = document.getElementById('apply-filters');\r
    if (applyFiltersBtn) {\r
        applyFiltersBtn.addEventListener('click', function() {\r
            filterResults();\r
        });\r
    }\r
    \r
    // Reset filters button\r
    const resetFiltersBtn = document.getElementById('reset-filters');\r
    if (resetFiltersBtn) {\r
        resetFiltersBtn.addEventListener('click', function() {\r
            resetFilters();\r
        });\r
    }\r
}

/**\r
 * Filter results based on search input\r
 */\r
function filterResults() {\r
    const searchInput = document.getElementById('search-results');\r
    const searchTerm = searchInput ? searchInput.value.toLowerCase() : '';\r
    \r
    const resultRows = document.querySelectorAll('.result-row');\r
    \r
    let visibleCount = 0;\r
    \r
    resultRows.forEach(row => {\r
        const url = row.querySelector('.url-cell').textContent.toLowerCase();\r
        \r
        // Check if matches search term\r
        const matchesSearch = searchTerm === '' || url.includes(searchTerm);\r
        \r
        // Show/hide row based on search\r
        row.style.display = matchesSearch ? '' : 'none';\r
        \r
        if (matchesSearch) {\r
            visibleCount++;\r
        }\r
    });\r
    \r
    // Update results count\r
    const resultsCountEl = document.querySelector('.results-count');\r
    if (resultsCountEl) {\r
        resultsCountEl.textContent = `Showing ${visibleCount} of ${resultRows.length} results`;\r
    }\r
}

/**\r
 * Reset all filters to default values\r
 */\r
function resetFilters() {\r
    // Reset search input\r
    const searchInput = document.getElementById('search-results');\r
    if (searchInput) {\r
        searchInput.value = '';\r
    }\r
    \r
    // Show all results\r
    const resultRows = document.querySelectorAll('.result-row');\r
    resultRows.forEach(row => {\r
        row.style.display = '';\r
    });\r
    \r
    // Update results count\r
    const resultsCountEl = document.querySelector('.results-count');\r
    if (resultsCountEl) {\r
        resultsCountEl.textContent = `Showing ${resultRows.length} of ${resultRows.length} results`;\r
    }\r
}

/**
 * Set up dynamic loading of results
 */
function setupResultsLoading() {
    // Check if we're on the results page
    const resultsContainer = document.querySelector('.results-container');
    if (!resultsContainer) return;
    
    // If the page has a data-results-file attribute, load those results
    const resultsFile = resultsContainer.dataset.resultsFile;
    if (resultsFile) {
        loadResults(resultsFile);
    }
}

/**
 * Load results from a JSON file
 * @param {string} filename - The name of the results file
 */
function loadResults(filename) {
    showLoading();
    
    fetch(`/results/${filename}`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            displayResults(data);
            hideLoading();
        })
        .catch(error => {
            console.error('Error loading results:', error);
            showAlert('Error loading results: ' + error.message, 'danger');
            hideLoading();
        });
}

/**
 * Display results in the results table
 * @param {Object} data - The results data
 */
function displayResults(data) {
    const resultsTable = document.querySelector('.results-table tbody');
    if (!resultsTable) return;
    
    resultsTable.innerHTML = '';
    
    let results = [];
    
    // Handle different formats of the results data
    if (Array.isArray(data)) {
        results = data;
    } else if (data.directories && Array.isArray(data.directories)) {
        results = data.directories.map(item => {
            if (typeof item === 'object') return item;
            return { url: item, status: 'N/A', size: 'N/A', response_time: 'N/A', content_type: 'N/A' };
        });
    } else if (data.subdomains && Array.isArray(data.subdomains)) {
        results = data.subdomains.map(item => {
            if (typeof item === 'object') return item;
            return { url: item, status: 'N/A', size: 'N/A', response_time: 'N/A', content_type: 'N/A' };
        });
    } else if (data.api_endpoints && Array.isArray(data.api_endpoints)) {
        results = data.api_endpoints.map(item => {
            if (typeof item === 'object') return item;
            return { url: item, status: 'N/A', size: 'N/A', response_time: 'N/A', content_type: 'N/A' };
        });
    }
    
    // Create rows for each result
    results.forEach(result => {
        const row = document.createElement('tr');
        row.className = 'result-row';
        
        row.innerHTML = `
            <td class="url-cell">${result.url || 'N/A'}</td>
            <td class="status-cell">${result.status || 'N/A'}</td>
            <td class="size-cell">${result.size || 'N/A'}</td>
            <td class="time-cell">${result.response_time || 'N/A'}</td>
            <td class="content-type-cell">${result.content_type || 'N/A'}</td>
            <td class="actions-cell">
                <button class="btn btn-sm btn-primary update-url-btn" data-url="${result.url}">Update</button>
                <button class="btn btn-sm btn-secondary copy-url-btn" data-url="${result.url}">Copy</button>
            </td>
        `;
        
        resultsTable.appendChild(row);
    });
    
    // Update the results count
    const resultsCountEl = document.querySelector('.results-count');
    if (resultsCountEl) {
        resultsCountEl.textContent = `Showing ${results.length} of ${results.length} results`;
    }
    
    // Setup action buttons
    setupActionButtons();
}

/**
 * Setup action buttons for each result row
 */
function setupActionButtons() {
    // Update URL buttons
    const updateButtons = document.querySelectorAll('.update-url-btn');
    updateButtons.forEach(button => {
        button.addEventListener('click', function() {
            const url = this.dataset.url;
            updateUrlData(url);
        });
    });
    
    // Copy URL buttons
    const copyButtons = document.querySelectorAll('.copy-url-btn');
    copyButtons.forEach(button => {
        button.addEventListener('click', function() {
            const url = this.dataset.url;
            navigator.clipboard.writeText(url)
                .then(() => {
                    showAlert('URL copied to clipboard', 'success');
                })
                .catch(err => {
                    console.error('Failed to copy URL:', err);
                    showAlert('Failed to copy URL', 'danger');
                });
        });
    });
}

/**
 * Set up URL data update functionality
 */
function setupUrlDataUpdates() {
    const updateAllBtn = document.getElementById('update-all-btn');
    if (updateAllBtn) {
        updateAllBtn.addEventListener('click', function() {
            updateAllUrls();
        });
    }
}

/**
 * Update data for a specific URL
 * @param {string} url - The URL to update
 */
function updateUrlData(url) {
    const resultsContainer = document.querySelector('.results-container');
    if (!resultsContainer) return;
    
    const resultsFile = resultsContainer.dataset.resultsFile;
    if (!resultsFile) return;
    
    showLoading();
    

/**
 * Web-Fuzzer - Main JavaScript functionality
 * - Table filtering and sorting
 * - Result exporting (CSV, JSON)
 * - Responsive UI controls
 */

document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

/**
 * Initialize the application
 */
function initializeApp() {
    // Initialize table sorting
    const tables = document.querySelectorAll('.results-table');
    tables.forEach(table => {
        initTableSort(table);
    });

    // Initialize filtering
    initializeFilters();
    
    // Initialize export buttons
    initializeExportButtons();
    
    // Initialize form validation
    initializeFormValidation();
    
    // Initialize responsive menu
    initializeResponsiveMenu();
}

/**
 * Table sorting functionality
 * @param {HTMLElement} table - The table element to make sortable
 */
function initTableSort(table) {
    const headers = table.querySelectorAll('th');
    
    headers.forEach(header => {
        if (header.classList.contains('no-sort')) return;
        
        header.addEventListener('click', function() {
            const isAscending = this.classList.contains('sort-asc');
            
            // Reset all headers
            headers.forEach(h => {
                h.classList.remove('sort-asc', 'sort-desc');
            });
            
            // Set new sort direction
            this.classList.add(isAscending ? 'sort-desc' : 'sort-asc');
            
            // Get column index
            const columnIndex = Array.from(this.parentNode.children).indexOf(this);
            
            // Sort the table
            sortTable(table, columnIndex, !isAscending);
        });
        
        // Add sort indicators and cursor pointer
        header.style.position = 'relative';
        header.style.cursor = 'pointer';
        header.innerHTML += '<span class="sort-indicator"></span>';
    });
}

/**
 * Sort table data
 * @param {HTMLElement} table - The table to sort
 * @param {number} columnIndex - Index of the column to sort by
 * @param {boolean} ascending - Sort direction
 */
function sortTable(table, columnIndex, ascending) {
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    
    // Sort the array of rows
    rows.sort((rowA, rowB) => {
        const cellA = rowA.querySelectorAll('td')[columnIndex].textContent.trim();
        const cellB = rowB.querySelectorAll('td')[columnIndex].textContent.trim();
        
        // Check if the content is a number
        const numA = parseFloat(cellA);
        const numB = parseFloat(cellB);
        
        if (!isNaN(numA) && !isNaN(numB)) {
            return ascending ? numA - numB : numB - numA;
        }
        
        // Otherwise, compare as strings
        return ascending 
            ? cellA.localeCompare(cellB) 
            : cellB.localeCompare(cellA);
    });
    
    // Remove existing rows
    while (tbody.firstChild) {
        tbody.removeChild(tbody.firstChild);
    }
    
    // Add sorted rows
    rows.forEach(row => {
        tbody.appendChild(row);
    });
}

/**
 * Initialize results filtering functionality
 */
function initializeFilters() {
    const searchInput = document.getElementById('search-box');
    const statusFilter = document.getElementById('status-filter');
    const typeFilter = document.getElementById('type-filter');
    
    if (!searchInput) return;
    
    // Function to filter table rows
    function filterTable() {
        const tables = document.querySelectorAll('.results-table');
        const searchTerm = searchInput.value.toLowerCase();
        const statusValue = statusFilter ? statusFilter.value : 'all';
        const typeValue = typeFilter ? typeFilter.value : 'all';
        
        tables.forEach(table => {
            const rows = table.querySelectorAll('tbody tr');

