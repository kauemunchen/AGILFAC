const fs = require('fs');
let code = fs.readFileSync('server.js', 'utf8');

// Injetar o link no topo do menu da sidebar
if (!code.includes('/operacional/crm-ops')) {
  code = code.replace(/<nav[^>]*>/, match => `${match}\n        <a href="/operacional/crm-ops" class="nav-item">🧵 CRM Kanban OPs</a>`);
}

fs.writeFileSync('server.js', code);
console.log('✅ Menu do CRM Kanban aplicado!');
