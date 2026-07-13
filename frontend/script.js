// Global state to store all findings and chart instance
let allFindings = [];
let severityChart = null;

// DOM Elements
const modeBadge = document.getElementById('mode-badge');
const totalCountEl = document.getElementById('total-count');
const highCountEl = document.getElementById('high-count');
const mediumCountEl = document.getElementById('medium-count');
const lowCountEl = document.getElementById('low-count');
const findingsBody = document.getElementById('findings-body');
const filterSeverity = document.getElementById('filter-severity');
const filterCategory = document.getElementById('filter-category');

// Initialize the dashboard
async function initDashboard() {
    try {
        // Fetch data from our Flask backend
        const response = await fetch('/api/findings');
        const data = await response.json();
        
        allFindings = data.findings || [];
        
        // Update the Mode Badge (Live vs Demo)
        if (data.mode === 'live') {
            modeBadge.textContent = 'Live Data';
            modeBadge.className = 'badge live-mode';
        } else {
            modeBadge.textContent = 'Demo Mode';
            modeBadge.className = 'badge demo-mode';
        }
        
        // Populate category dropdown based on available data
        populateCategoryFilter();
        
        // Render initial view
        updateDashboard(allFindings);
        
    } catch (error) {
        console.error('Error fetching data:', error);
        findingsBody.innerHTML = `<tr><td colspan="5" class="loading-state" style="color: var(--color-high);">Error loading data. Is the backend running?</td></tr>`;
    }
}

// Populate the Category filter dropdown dynamically
function populateCategoryFilter() {
    const categories = new Set(allFindings.map(f => f.category));
    categories.forEach(category => {
        const option = document.createElement('option');
        option.value = category;
        option.textContent = category;
        filterCategory.appendChild(option);
    });
}

// Update the entire dashboard (cards, chart, table) based on a filtered list
function updateDashboard(findings) {
    updateSummaryCards(findings);
    updateTable(findings);
    updateChart(findings);
}

// Update the numeric summary cards
function updateSummaryCards(findings) {
    const counts = { High: 0, Medium: 0, Low: 0 };
    
    findings.forEach(f => {
        if (counts[f.severity] !== undefined) {
            counts[f.severity]++;
        }
    });
    
    totalCountEl.textContent = findings.length;
    highCountEl.textContent = counts.High;
    mediumCountEl.textContent = counts.Medium;
    lowCountEl.textContent = counts.Low;
}

// Update the findings table
function updateTable(findings) {
    findingsBody.innerHTML = '';
    
    if (findings.length === 0) {
        findingsBody.innerHTML = `<tr><td colspan="5" class="loading-state">No findings match the current filters.</td></tr>`;
        return;
    }
    
    findings.forEach(finding => {
        const tr = document.createElement('tr');
        
        // Setup severity badge HTML
        const severityLower = finding.severity.toLowerCase();
        const badgeClass = `severity-badge severity-${severityLower}`;
        
        tr.innerHTML = `
            <td><strong>${finding.resource_name}</strong></td>
            <td>${finding.category}</td>
            <td><span class="${badgeClass}">${finding.severity}</span></td>
            <td>${finding.description}</td>
            <td><em>${finding.recommendation}</em></td>
        `;
        findingsBody.appendChild(tr);
    });
}

// Render or update the Chart.js doughnut chart
function updateChart(findings) {
    const counts = { High: 0, Medium: 0, Low: 0 };
    findings.forEach(f => {
        if (counts[f.severity] !== undefined) counts[f.severity]++;
    });
    
    const ctx = document.getElementById('severityChart').getContext('2d');
    
    const data = {
        labels: ['High', 'Medium', 'Low'],
        datasets: [{
            data: [counts.High, counts.Medium, counts.Low],
            backgroundColor: [
                '#ef4444', // High (Red)
                '#f59e0b', // Medium (Amber)
                '#10b981'  // Low (Emerald)
            ],
            borderWidth: 0,
            hoverOffset: 4
        }]
    };
    
    const options = {
        responsive: true,
        cutout: '70%',
        plugins: {
            legend: {
                position: 'bottom',
                labels: {
                    color: '#f8fafc',
                    padding: 20,
                    usePointStyle: true,
                }
            }
        }
    };

    // Destroy existing chart if it exists to render a new one smoothly
    if (severityChart) {
        severityChart.destroy();
    }
    
    severityChart = new Chart(ctx, {
        type: 'doughnut',
        data: data,
        options: options
    });
}

// Filter logic: triggered on dropdown change
function handleFilters() {
    const severityVal = filterSeverity.value;
    const categoryVal = filterCategory.value;
    
    const filtered = allFindings.filter(f => {
        const matchSeverity = severityVal === 'All' || f.severity === severityVal;
        const matchCategory = categoryVal === 'All' || f.category === categoryVal;
        return matchSeverity && matchCategory;
    });
    
    updateDashboard(filtered);
}

// Event Listeners for Filters
filterSeverity.addEventListener('change', handleFilters);
filterCategory.addEventListener('change', handleFilters);

// Start the app on load
document.addEventListener('DOMContentLoaded', initDashboard);

// --- Navigation Logic ---
const navLinks = document.querySelectorAll('.nav-links li');
const pageSections = document.querySelectorAll('.page-section');
const pageTitle = document.getElementById('page-title');

const sectionTitles = {
    'dashboard': 'Security Posture Overview',
    'resources': 'Cloud Resources',
    'settings': 'Settings'
};

navLinks.forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        const target = link.getAttribute('data-target');
        
        // Update active class
        navLinks.forEach(l => l.classList.remove('active'));
        link.classList.add('active');
        
        // Update visible section
        pageSections.forEach(sec => sec.style.display = 'none');
        document.getElementById(`section-${target}`).style.display = 'block';
        
        // Update Title
        if(sectionTitles[target]) {
            pageTitle.textContent = sectionTitles[target];
        }
        
        // Render resources if resources tab is clicked
        if (target === 'resources') {
            updateResourcesTable(allFindings);
        }
    });
});

// --- Resources Logic ---
function updateResourcesTable(findings) {
    const resourcesBody = document.getElementById('resources-body');
    resourcesBody.innerHTML = '';
    
    if (findings.length === 0) {
        resourcesBody.innerHTML = `<tr><td colspan="3" class="loading-state">No resources found.</td></tr>`;
        return;
    }
    
    // Aggregate by resource_name
    const resourcesMap = {};
    findings.forEach(f => {
        if (!resourcesMap[f.resource_name]) {
            resourcesMap[f.resource_name] = {
                type: f.category,
                findingsCount: 0,
                highestSeverity: 'Low'
            };
        }
        resourcesMap[f.resource_name].findingsCount++;
        
        // Upgrade severity logic
        const sevOrder = {'High': 3, 'Medium': 2, 'Low': 1};
        const currentHighest = resourcesMap[f.resource_name].highestSeverity;
        if (sevOrder[f.severity] > sevOrder[currentHighest]) {
            resourcesMap[f.resource_name].highestSeverity = f.severity;
        }
    });
    
    Object.keys(resourcesMap).forEach(resName => {
        const res = resourcesMap[resName];
        const tr = document.createElement('tr');
        
        const badgeClass = `severity-badge severity-${res.highestSeverity.toLowerCase()}`;
        const statusText = `${res.findingsCount} finding${res.findingsCount > 1 ? 's' : ''}`;
        
        tr.innerHTML = `
            <td><strong>${resName}</strong></td>
            <td>${res.type}</td>
            <td>
                <span class="${badgeClass}">${res.highestSeverity} Risk</span>
                <span style="margin-left: 8px; color: var(--text-secondary); font-size: 0.85rem;">(${statusText})</span>
            </td>
        `;
        resourcesBody.appendChild(tr);
    });
}

// --- Settings Logic ---
const saveSettingsBtn = document.getElementById('save-settings-btn');
const saveMessage = document.getElementById('save-message');

if (saveSettingsBtn) {
    saveSettingsBtn.addEventListener('click', () => {
        saveMessage.style.display = 'inline-block';
        setTimeout(() => {
            saveMessage.style.display = 'none';
        }, 3000);
    });
}
