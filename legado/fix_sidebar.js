const fs = require('fs');
let code = fs.readFileSync('server.js', 'utf8');

// Adicionar o item do Kanban na lista de itens da barra lateral
if (!code.includes("path: '/operacional/crm-ops'")) {
  code = code.replace(
    /const navItems = \[/,
    `const navItems = [\n    { path: '/operacional/crm-ops', label: 'CRM OPs', icon: '🧵' },`
  );
}

fs.writeFileSync('server.js', code);
console.log('✅ Sidebar atualizado com sucesso!');
