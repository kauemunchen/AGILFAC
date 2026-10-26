# Estrutura inicial do banco de dados

## Tabelas principais
- `users`: usuários do sistema e perfis de acesso
- `employees`: colaboradores/operadores
- `brands`: base oficial de marcas cadastradas
- `collections`: base oficial de coleções cadastradas
- `app_settings`: configurações simples da aplicação (ex.: nome da empresa nas etiquetas)
- `ops`: cadastro principal das OPs, incluindo coleção, piloto e aparelho
- `op_daily_productions`: lançamentos diários de produção
- `op_occurrences`: ocorrências manuais das OPs
- `shipments`: cabeçalho dos embarques
- `shipment_items`: OPs incluídas em cada embarque
- `op_extra_times`: cadastro de minutos extras por peça para OP, aplicado somente nos lançamentos diários

## Regras refletidas no schema
- Perfis: adm, operacional, resultados
- F23 interno exige minutos F23
- OP começa com status verde
- Status possíveis: verde, amarelo, azul, vermelho
- Devolução sem produção / não industrializada não deve gerar contadores
- Cálculo de eficiência usa apenas F21 no MVP
- Resultado diário usa base fixa de 528 minutos
- Tempo extra de OP soma minutos apenas no lançamento diário; embarque continua usando somente F21

## Views incluídas
- `v_op_production_summary`: resumo de quantidade produzida e saldo da OP
- `v_employee_daily_result`: resultado diário por colaborador
