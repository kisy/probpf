// Helpers
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function formatSpeed(bytesPerSec) {
    return formatBytes(bytesPerSec) + '/s';
}

function formatTime(isoString) {
    if (!isoString || isoString.startsWith('0001')) return '-';
    return new Date(isoString).toLocaleTimeString();
}

function formatDuration(seconds) {
    if (!seconds) return '0s';
    if (seconds < 60) return seconds + 's';
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    if (mins < 60) return `${mins}m ${secs}s`;
    const hrs = Math.floor(mins / 60);
    const m = mins % 60;
    return `${hrs}h ${m}m`;
}

async function copyText(text) {
    try {
        if (navigator.clipboard) {
            await navigator.clipboard.writeText(text);
        } else {
            const ta = document.createElement('textarea');
            ta.value = text;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
        }
        showToast(`Copied: ${text}`);
    } catch (e) {
        console.error('Copy failed', e);
    }
}

function showToast(msg) {
    let el = document.getElementById('toast');
    if (!el) {
        el = document.createElement('div');
        el.id = 'toast';
        el.style.cssText = 'position:fixed; bottom:20px; left:50%; transform:translateX(-50%); background:var(--pico-primary-inverse); color:var(--pico-primary); padding:8px 16px; border-radius:4px; font-size:14px; z-index:9999; transition: opacity 0.3s; pointer-events:none;';
        document.body.appendChild(el);
    }
    el.textContent = msg;
    el.style.opacity = '1';
    setTimeout(() => { el.style.opacity = '0'; }, 2000);
}



// Theme Helper
function getInitialTheme() {
    const persisted = localStorage.getItem('probpf_theme');
    if (persisted) return persisted;
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('probpf_theme', theme);
}

// Alpine Initialization
document.addEventListener('alpine:init', () => {
    
    // === Clients List App ===
    // === Clients List App ===
    Alpine.data('clientsApp', () => ({
        clients: [],
        global: {},
        search: '',
        sortBy: localStorage.getItem('probpf_sortBy') || 'total_download',
        sortDesc: localStorage.getItem('probpf_sortDesc') === 'true',
        startTime: '',
        autoRefresh: true,
        theme: getInitialTheme(),

        init() {
            // Restore defaults if logic failed
            if (!this.sortBy) { this.sortBy = 'total_download'; this.sortDesc = true; }
            
            // Apply Initial Theme
            applyTheme(this.theme);

            this.fetchData();
            setInterval(() => {
                if (this.autoRefresh) this.fetchData();
            }, 1000);
        },

        async fetchData() {
            try {
                const res = await fetch('/api/stats');
                const data = await res.json();
                this.clients = data.clients || [];
                this.global = data.global || {};
                this.startTime = data.start_time;
            } catch (e) {
                console.error(e);
            }
        },

        get sortedClients() {
            if (!this.clients) return [];
            
            let list = this.clients.filter(c => {
                const q = this.search.toLowerCase();
                return !q || 
                    (c.name || '').toLowerCase().includes(q) || 
                    c.mac.toLowerCase().includes(q) || 
                    (c.ips && c.ips.some(ip => ip.includes(q)));
            });

            return list.sort((a, b) => {
                let va = this.getValue(a, this.sortBy);
                let vb = this.getValue(b, this.sortBy);
                
                let res = 0;
                if (va < vb) res = this.sortDesc ? 1 : -1;
                else if (va > vb) res = this.sortDesc ? -1 : 1;

                if (res === 0) {
                    // Secondary Name Sort
                    if ((a.name||'') < (b.name||'')) return -1;
                    if ((a.name||'') > (b.name||'')) return 1;
                }
                return res;
            });
        },

        getValue(obj, key) {
            if (key === 'started') return obj.start_time;
            return obj[key] || 0;
        },

        setSort(col) {
            if (this.sortBy === col) {
                this.sortDesc = !this.sortDesc;
            } else {
                this.sortBy = col;
                this.sortDesc = true;
            }
            localStorage.setItem('probpf_sortBy', this.sortBy);
            localStorage.setItem('probpf_sortDesc', this.sortDesc);
        },

        setMobileSort(val) {
            const [col, dir] = val.split(':');
            this.sortBy = col;
            this.sortDesc = dir === 'desc';
            localStorage.setItem('probpf_sortBy', this.sortBy);
            localStorage.setItem('probpf_sortDesc', this.sortDesc);
        },

        async resetAll() {
            if (!confirm('Clear ALL statistics?')) return;
            await fetch('/api/reset', { method: 'POST' });
            this.fetchData();
        },

        toggleTheme() {
            this.theme = this.theme === 'dark' ? 'light' : 'dark';
            applyTheme(this.theme);
        }
    }));


    // === Detail App ===
    // === Detail App ===
    Alpine.data('detailApp', () => ({
        mac: new URLSearchParams(window.location.search).get('mac'),
        client: {},
        flows: [],
        filterProtocol: '',
        filterRemoteIP: '',
        filterRemotePort: '',
        ipProvider: localStorage.getItem('probpf_ipProvider') || 'https://ipinfo.io/',
        autoRefresh: true,
        theme: getInitialTheme(),
        
        // Flow Sorting
        sortBy: 'session_download',
        sortDesc: true,

        init() {
            if (!this.mac) {
                window.location.href = '/clients';
                return;
            }
            
            // Apply Initial Theme
            applyTheme(this.theme);

            this.fetchData();
            setInterval(() => {
                if (this.autoRefresh) this.fetchData();
            }, 1000);
        },

        async fetchData() {
            try {
                const res = await fetch(`/api/client?mac=${this.mac}`);
                const data = await res.json();
                this.client = data.client || {};
                this.flows = data.flows || [];
            } catch (e) { console.error(e); }
        },
        // ... (intermediate code for uniqueIPs and filteredFlows, keeping mostly same but need to be careful with range)
        
        get uniqueIPs() {
            const ips = new Set();
            this.flows.forEach(f => {
                if (f.local_ip && f.local_ip !== '-') ips.add(f.local_ip);
            });
            return Array.from(ips).sort();
        },

        get filteredFlows() {
            if (!this.flows) return [];
            
            let list = this.flows.filter(f => {
                 if (this.filterProtocol && !f.protocol.toLowerCase().includes(this.filterProtocol.toLowerCase())) return false;
                 if (this.filterRemoteIP && !f.remote_ip.includes(this.filterRemoteIP)) return false;
                 if (this.filterRemotePort && !(f.remote_port + '').includes(this.filterRemotePort)) return false;
                 return true;
            });

            return list.sort((a, b) => {
                let va = a[this.sortBy];
                let vb = b[this.sortBy];
                
                let res = 0;
                if (va < vb) res = this.sortDesc ? 1 : -1;
                else if (va > vb) res = this.sortDesc ? -1 : 1;
                
                if (res === 0) {
                     if (a.remote_ip < b.remote_ip) return -1;
                     if (a.remote_ip > b.remote_ip) return 1;
                }
                return res;
            });
        }, 
        // ... (keeping methods)

        setSort(col) {
            if (this.sortBy === col) {
                this.sortDesc = !this.sortDesc;
            } else {
                this.sortBy = col;
                this.sortDesc = true;
            }
        },

        setMobileSort(val) {
            const [col, dir] = val.split(':');
            this.sortBy = col;
            this.sortDesc = dir === 'desc';
        },

        setProvider(val) {
            this.ipProvider = val;
            localStorage.setItem('probpf_ipProvider', val);
        },

        clearFilters() {
            this.filterProtocol = '';
            this.filterRemoteIP = '';
            this.filterRemotePort = '';
        },
        
        renderResponsiveIP(ip, linkable = true) {
            if (!ip) return '';
            
            let html = ip;
            
            // Smart IPv6 Truncation
            if (ip.includes(':') && ip.length > 15) { // Truncate longer IPv6
                const parts = ip.split(':');
                // Simple logic: Keep first 2 segments and last 1 segment
                if (parts.length > 3) {
                     const head = parts.slice(0, 2).join(':');
                     const tail = parts[parts.length - 1];
                     html = `<div class="ip-smart">
                               <span class="ip-part-head">${head}:</span>
                               <span class="ip-part-mid">~</span>
                                <span class="ip-part-tail">:${tail}</span>
                             </div>`;
                }
            }

            if (linkable) {
                const url = this.ipProvider + ip;
                html = `<a href="${url}" target="_blank" class="ip-link">${html}</a>`;
            }

            return `<div class="ip-cell">
                        ${html}
                        <button class="copy-btn" onclick="copyText('${ip}')" title="Copy IP">
                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                        </button>
                    </div>`;
        },
        
        async resetSession() {
            if (!confirm('Reset SESSION stats (duration, traffic) for this client?')) return;
            await fetch(`/api/client/reset_session?mac=${this.mac}`, { method: 'POST' });
            this.fetchData();
        },

        async resetGlobal() {
            if (!confirm(`Reset GLOBAL stats (history) for this client? This cannot be undone.`)) return;
            await fetch(`/api/client/reset?mac=${this.mac}`, { method: 'POST' });
            this.fetchData();
        },

        toggleTheme() {
            this.theme = this.theme === 'dark' ? 'light' : 'dark';
            applyTheme(this.theme);
        }
    }));
});
