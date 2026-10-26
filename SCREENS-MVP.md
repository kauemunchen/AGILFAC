# Telas do MVP - App Controle de OPs

## 1. Login
### Objetivo
Permitir acesso dos usuários ao sistema.

### Elementos principais
- Usuário
- Senha
- Botão entrar
- Recuperação de acesso (opcional para depois)

### Quem acessa
- Adm
- Operacional
- Resultados

---

## 2. Dashboard (Tela inicial)
### Objetivo
Dar visão geral do resultado da empresa e da produção.

### Elementos principais
- Cards com totais produzidos
- Cards com totais a produzir
- Resultado diário da empresa
- Resultado semanal da empresa
- Resultado mensal operacional da empresa
- Resultado por colaborador
- Filtros por dia, semana e mês operacional
- Ranking/resumo de colaboradores
- Resumo de OPs por status

### Quem acessa
- Adm
- Resultados
- Operacional (se desejar, com visão limitada)

---

## 3. Cadastro de OPs
### Objetivo
Cadastrar novas ordens de produção no sistema.

### Campos principais
- Código de barras da OP
- Número da OP
- Produto
- Tipo da OP (Produção ou Mostruário)
- Marca
- Quantidade total de peças
- Minutos F21
- Minutos F22
- F23 interno ou externo
- Minutos F23
- Data de entrada automática
- Observações
- Quem fez a entrada

### Regras principais
- Ao cadastrar, a OP entra com status Verde
- Se F23 for interno, minutos F23 obrigatórios
- Se F23 for externo, minutos F23 podem ficar desabilitados

### Quem acessa
- Adm
- Operacional

---

## 4. Lista / Consulta de OPs
### Objetivo
Permitir pesquisar e localizar OPs rapidamente.

### Elementos principais
- Busca por número da OP
- Busca por código de barras
- Filtros por status
- Filtros por tipo (Produção / Mostruário)
- Filtros por período de entrada
- Lista com status, produto, quantidade, saldo e datas

### Quem acessa
- Adm
- Operacional
- Resultados

---

## 5. Consulta detalhada da OP
### Objetivo
Exibir a ficha completa da OP.

### Blocos da tela
#### 5.1 Dados da OP
- Todos os dados cadastrais
- Status atual

#### 5.2 Entrada
- Data de entrada
- Quem fez a entrada

#### 5.3 Histórico de produção
- Colaborador
- Data de produção
- Quantidade produzida
- Total acumulado

#### 5.4 Histórico de ocorrências
- Ocorrência manual
- Data da ocorrência
- Status da ocorrência
- Justificativa de conclusão

#### 5.5 Saída
- Data de saída
- Informação de embarque
- Situação de devolução sem produção, se houver

### Quem acessa
- Adm
- Operacional
- Resultados

---

## 6. Abastecimento
### Objetivo
Mostrar as OPs internas disponíveis/em andamento para produção.

### Elementos principais
- Lista de OPs verdes
- Saldo a produzir por OP
- Quantidade já produzida
- Quantidade faltante
- Alertas de pendência
- Busca e filtros

### Quem acessa
- Adm
- Operacional

---

## 7. Lançamento diário de produção
### Objetivo
Registrar a produção diária dos colaboradores.

### Campos principais
- Colaborador (por código de registro)
- OP
- Quantidade produzida
- Data

### Regras principais
- O cálculo do MVP usa somente F21
- O sistema calcula automaticamente os minutos produzidos
- O sistema compara o acumulado com a quantidade total da OP
- Deve informar se falta, se atingiu ou se ultrapassou a quantidade da OP
- Ao atingir a quantidade total, a OP fica Azul

### Quem acessa
- Adm
- Operacional

---

## 8. Cadastro de colaboradores
### Objetivo
Cadastrar operadores que terão produção lançada.

### Campos principais
- Código de registro
- Nome
- Status ativo/inativo
- Observações

### Quem acessa
- Adm
- Operacional

---

## 9. Ocorrências / Pendências da OP
### Objetivo
Registrar problemas e paralisações da OP.

### Campos principais
- OP
- Texto da ocorrência
- Data da ocorrência
- Status da ocorrência
- Justificativa de conclusão

### Regras principais
- Ao abrir ocorrência, OP fica Amarela
- Ao concluir ocorrência com justificativa, OP volta para Verde

### Quem acessa
- Adm
- Operacional

---

## 10. Módulo de embarque
### Objetivo
Selecionar OPs concluídas para envio ao fornecedor.

### Elementos principais
- Busca por OP
- Filtros por tipo
- Seleção por flag/checkbox
- Lista das OPs selecionadas
- Botão Gerar embarque

### Regras principais
- Só pode embarcar OP concluída em costura
- Ao embarcar, registrar data de saída
- Ao embarcar, OP fica Vermelha
- Consolidar minutos por:
  - Produção
  - Mostruário
  - F21 + F22
  - F23

### Quem acessa
- Adm
- Operacional

---

## 11. Devolução sem produção / Não industrializada
### Objetivo
Registrar OPs que não serão produzidas.

### Campos principais
- OP
- Motivo / justificativa
- Data do registro
- Usuário responsável

### Regras principais
- Não gera contadores de produção
- Fica registrado no histórico da OP

### Quem acessa
- Adm
- Operacional

---

## 12. Relatório de embarque
### Objetivo
Acompanhar o que foi embarcado por período.

### Elementos principais
- Filtro por dia
- Filtro por semana
- Filtro por mês operacional
- Total de minutos embarcados de produção
- Total de minutos embarcados de mostruário
- Total F21 + F22
- Total F23
- Quantidade de OPs embarcadas

### Quem acessa
- Adm
- Resultados

---

## 13. Cadastro de usuários e permissões
### Objetivo
Gerenciar acessos ao sistema.

### Funções principais
- Criar usuário
- Editar usuário
- Definir perfil
- Ativar/desativar acesso

### Perfis
- Adm
- Operacional
- Resultados

### Quem acessa
- Adm

---

## 14. Relatório / Resultado por colaborador
### Objetivo
Consultar desempenho individual e consolidado.

### Elementos principais
- Filtro por colaborador
- Filtro por dia
- Filtro por semana
- Filtro por mês operacional
- Minutos produzidos
- Percentual de resultado
- Histórico por período

### Quem acessa
- Adm
- Resultados

---

## MVP Essencial (ordem de prioridade)
### Prioridade 1
- Login
- Dashboard
- Cadastro de OPs
- Lista / Consulta de OPs
- Consulta detalhada da OP
- Abastecimento
- Lançamento diário
- Cadastro de colaboradores

### Prioridade 2
- Ocorrências / Pendências
- Embarque
- Devolução sem produção
- Cadastro de usuários e permissões

### Prioridade 3
- Relatório de embarque
- Relatório por colaborador
