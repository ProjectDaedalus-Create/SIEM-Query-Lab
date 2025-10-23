// SIEM Query Lab - Main Application Logic

class SiemQueryLab {
    constructor() {
        this.currentLanguage = 'sql';
        this.currentModule = null;
        this.completedModules = new Set();
        this.dataCache = {};
        this.queryEngine = new QueryEngine();
        
        this.init();
    }
    
    async init() {
        await this.loadAllData();
        this.setupEventListeners();
        this.renderModules();
        this.updateProgress();
    }
    
    async loadAllData() {
        const dataSources = ['auth_logs', 'network_traffic', 'dns_logs', 'process_events'];
        
        for (const source of dataSources) {
            try {
                const response = await fetch(`data/${source}.json`);
                this.dataCache[source] = await response.json();
            } catch (error) {
                console.error(`Failed to load ${source}:`, error);
                this.dataCache[source] = [];
            }
        }
    }
    
    setupEventListeners() {
        // Language selector
        document.querySelectorAll('.lang-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                document.querySelectorAll('.lang-btn').forEach(b => b.classList.remove('active'));
                e.target.classList.add('active');
                this.currentLanguage = e.target.dataset.lang;
                this.renderModules();
            });
        });
        
        // Query editor buttons
        const runBtn = document.getElementById('runQueryBtn');
        const clearBtn = document.getElementById('clearBtn');
        const hintBtn = document.getElementById('hintBtn');
        
        if (runBtn) runBtn.addEventListener('click', () => this.runQuery());
        if (clearBtn) clearBtn.addEventListener('click', () => this.clearEditor());
        if (hintBtn) hintBtn.addEventListener('click', () => this.showHint());
        
        // Data source selector
        const dataSourceSelect = document.getElementById('dataSourceSelect');
        if (dataSourceSelect) {
            dataSourceSelect.addEventListener('change', () => this.updateDataSource());
        }
    }
    
    renderModules() {
        const moduleList = document.getElementById('moduleList');
        const modules = CHALLENGES[this.currentLanguage] || [];
        
        moduleList.innerHTML = '';
        
        modules.forEach((module, index) => {
            const moduleEl = document.createElement('div');
            moduleEl.className = 'module-item';
            if (this.completedModules.has(`${this.currentLanguage}-${index}`)) {
                moduleEl.classList.add('completed');
            }
            if (this.currentModule === index) {
                moduleEl.classList.add('active');
            }
            
            const typeColors = {
                'theory': 'badge-theory',
                'guided': 'badge-practice',
                'practical': 'badge-practice',
                'challenge': 'badge-challenge'
            };
            
            moduleEl.innerHTML = `
                <div class="module-title">${module.title}</div>
                <span class="badge ${typeColors[module.type]}">${module.type.toUpperCase()}</span>
            `;
            
            moduleEl.addEventListener('click', () => this.loadModule(index));
            moduleList.appendChild(moduleEl);
        });
    }
    
    loadModule(index) {
        this.currentModule = index;
        const module = CHALLENGES[this.currentLanguage][index];
        
        document.getElementById('lessonContainer').style.display = 'block';
        document.getElementById('queryWorkspace').style.display = module.type !== 'theory' ? 'block' : 'none';
        
        this.renderLesson(module);
        this.renderModules();
    }
    
    renderLesson(module) {
        const container = document.getElementById('lessonContainer');
        
        let content = `
            <div class="lesson-content">
                <h3>${module.title}</h3>
                <span class="badge ${module.type === 'theory' ? 'badge-theory' : module.type === 'challenge' ? 'badge-challenge' : 'badge-practice'}">
                    ${module.type.toUpperCase()}
                </span>
        `;
        
        if (module.description) {
            content += `<p>${module.description}</p>`;
        }
        
        if (module.theory) {
            content += `<div class="theory-section">`;
            module.theory.forEach(point => {
                content += `<p>${point}</p>`;
            });
            content += `</div>`;
        }
        
        if (module.examples) {
            content += `<h4>Examples:</h4>`;
            module.examples.forEach(ex => {
                content += `
                    <p><strong>${ex.description}</strong></p>
                    <pre><code>${this.escapeHtml(ex.query)}</code></pre>
                `;
            });
        }
        
        if (module.task) {
            content += `
                <div class="task-section" style="background: var(--bg-tertiary); padding: var(--space-md); border-radius: var(--radius-md); margin-top: var(--space-lg);">
                    <h4 style="color: var(--accent-amber);">📋 Your Task:</h4>
                    <p>${module.task}</p>
                </div>
            `;
        }
        
        content += `</div>`;
        container.innerHTML = content;
        
        // Setup query workspace if applicable
        if (module.type !== 'theory') {
            const editor = document.getElementById('queryEditor');
            const dataSourceSelect = document.getElementById('dataSourceSelect');
            
            if (module.starterQuery) {
                editor.value = module.starterQuery;
            } else {
                editor.value = '';
            }
            
            if (module.dataSource) {
                dataSourceSelect.value = module.dataSource;
            }
            
            document.getElementById('workspaceTitle').textContent = module.title;
        }
    }
    
    runQuery() {
        const editor = document.getElementById('queryEditor');
        const dataSourceSelect = document.getElementById('dataSourceSelect');
        const resultsContent = document.getElementById('resultsContent');
        const resultCount = document.getElementById('resultCount');
        
        const query = editor.value.trim();
        if (!query) {
            resultsContent.innerHTML = '<p class="text-error">Please enter a query</p>';
            return;
        }
        
        const dataSource = dataSourceSelect.value;
        const data = this.dataCache[dataSource];
        
        try {
            const results = this.queryEngine.execute(query, data, this.currentLanguage);
            
            if (results.length === 0) {
                resultsContent.innerHTML = '<p class="text-warning">No results found</p>';
                resultCount.textContent = '0 rows';
            } else {
                resultCount.textContent = `${results.length} row${results.length !== 1 ? 's' : ''}`;
                resultsContent.innerHTML = this.renderTable(results);
                
                // Check if challenge is completed
                this.checkCompletion(results);
            }
        } catch (error) {
            resultsContent.innerHTML = `<p class="text-error">Error: ${this.escapeHtml(error.message)}</p>`;
            resultCount.textContent = 'Error';
        }
    }
    
    renderTable(results) {
        if (!results || results.length === 0) return '';
        
        const keys = Object.keys(results[0]);
        
        let html = '<table class="results-table"><thead><tr>';
        keys.forEach(key => {
            html += `<th>${this.escapeHtml(key)}</th>`;
        });
        html += '</tr></thead><tbody>';
        
        results.forEach(row => {
            html += '<tr>';
            keys.forEach(key => {
                const value = row[key];
                const displayValue = value === null || value === undefined ? 'NULL' : 
                                   typeof value === 'object' ? JSON.stringify(value) : 
                                   String(value);
                html += `<td>${this.escapeHtml(displayValue)}</td>`;
            });
            html += '</tr>';
        });
        
        html += '</tbody></table>';
        return html;
    }
    
    checkCompletion(results) {
        const module = CHALLENGES[this.currentLanguage][this.currentModule];
        
        if (module.validation && module.validation(results)) {
            const moduleKey = `${this.currentLanguage}-${this.currentModule}`;
            if (!this.completedModules.has(moduleKey)) {
                this.completedModules.add(moduleKey);
                this.showCompletionMessage();
                this.updateProgress();
                this.renderModules();
            }
        }
    }
    
    showCompletionMessage() {
        const resultsContent = document.getElementById('resultsContent');
        const successMsg = document.createElement('div');
        successMsg.style.cssText = 'background: var(--accent-green); color: white; padding: var(--space-md); border-radius: var(--radius-md); margin-top: var(--space-md); text-align: center; font-weight: bold;';
        successMsg.textContent = '✓ Challenge Completed! Great work!';
        resultsContent.insertBefore(successMsg, resultsContent.firstChild);
    }
    
    clearEditor() {
        document.getElementById('queryEditor').value = '';
        document.getElementById('resultsContent').innerHTML = '<p class="placeholder-text">Run a query to see results</p>';
        document.getElementById('resultCount').textContent = '';
    }
    
    showHint() {
        const module = CHALLENGES[this.currentLanguage][this.currentModule];
        if (module.hint) {
            alert(`Hint: ${module.hint}`);
        } else {
            alert('No hint available for this module.');
        }
    }
    
    updateDataSource() {
        const dataSourceSelect = document.getElementById('dataSourceSelect');
        console.log(`Switched to data source: ${dataSourceSelect.value}`);
    }
    
    updateProgress() {
        const totalModules = CHALLENGES[this.currentLanguage]?.length || 0;
        const completed = Array.from(this.completedModules).filter(key => 
            key.startsWith(this.currentLanguage)
        ).length;
        
        const percentage = totalModules > 0 ? Math.round((completed / totalModules) * 100) : 0;
        
        document.getElementById('progressFill').style.width = `${percentage}%`;
        document.getElementById('progressText').textContent = `${percentage}% Complete (${completed}/${totalModules})`;
    }
    
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Global functions
function startLearning() {
    document.querySelector('.welcome-screen').style.display = 'none';
    app.loadModule(0);
}

// Initialize app
let app;
document.addEventListener('DOMContentLoaded', () => {
    app = new SiemQueryLab();
});
