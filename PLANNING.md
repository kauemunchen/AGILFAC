# Planejamento - AgilFac

## 1. Objetivo do app
Controlar as Ordens de Produção recebidas na empresa e, a partir das informações registradas, pontuar a eficiência diária de cada colaborador, permitindo acompanhar o resultado diário, semanal e mensal da empresa.

## 2. Módulos definidos
### 2.1 Cadastro de OPs
Entrada das Ordens de Produção no sistema.

### 2.2 Abastecimento
Tela/área para visualizar as OPs que estão dentro da fábrica e ainda precisam ser produzidas.

### 2.3 Cadastro de colaboradores
Cadastro dos operadores/colaboradores para posterior apuração individual de resultado.

### 2.4 Lançamento diário
Registro da produção diária, que servirá de base para o cálculo de resultado individual e consolidado.

### 2.5 Embarque
Módulo para seleção de OPs que irão ao fornecedor, geração do embarque do dia e consolidação dos minutos embarcados por tipo e etapa.

### 2.6 Cadastro de usuários e permissões
Gestão de usuários do sistema e seus perfis de acesso.

## 3. Perfis iniciais
- Adm
- Operacional
- Resultados

## 4. Dashboard
Tela inicial com:
- total produzido
- total a produzir
- resultados da empresa
- resultados por colaborador
- filtros por dia, semana e mês operacional

## 5. Regra de negócio importante
O mês operacional da empresa vai do dia 26 até o dia 25 do mês seguinte.

## 6. Definições já detalhadas
### 6.1 Campos da OP
- Código de barras da OP
- Número da OP
- Produto
- Tipo/flag: Produção ou Mostruário
- Marca
- Quantidade total de peças
- Minutos F21
- Minutos F22
- F23: interno ou externo
- Minutos F23
- Data de entrada automática
- Observações

### 6.2 Regra da F23
- Se F23 = interno, minutos F23 obrigatórios
- Se F23 = externo, minutos F23 podem ficar desabilitados

### 6.3 Campos do lançamento diário
- Colaborador (por código de registro)
- OP
- Quantidade produzida
- Data

### 6.4 Regra de cálculo do resultado do colaborador
- Base diária padrão: 528 minutos
- Cada lançamento gera minutos produzidos a partir da quantidade produzida × minutos da fase correspondente
- O resultado diário do colaborador será: minutos produzidos no dia / 528

### 6.5 Status das OPs
- Verde = interno para produzir
- Amarelo = com pendência/ocorrência aguardando retorno
- Azul = concluída em costura
- Vermelho = embarcou para fornecedor

### 6.6 Regra de quantidade da OP
- O sistema deve controlar a quantidade produzida acumulada por OP
- Deve informar se falta quantidade para concluir
- Deve alertar se houver excesso/ultrapassagem da quantidade cadastrada
- Ao atingir a quantidade total da OP, o status muda para azul

## 7. Definições adicionais fechadas
- O cálculo do lançamento diário usará somente os minutos de F21
- Não haverá campo de fase no MVP
- Os 528 minutos serão fixos para todos os colaboradores
- O status amarelo terá ocorrência em texto
- A ocorrência poderá ser concluída com justificativa, retornando a OP para verde

## 8. Definições adicionais importantes
- Cada OP terá histórico de produção por colaborador
- O histórico mostrará colaborador, quantidade produzida e dias de produção
- O histórico será formado a partir dos lançamentos diários vinculados à OP
- Haverá uma tela de consulta detalhada da OP
- A consulta mostrará dados cadastrais, data de entrada, quem fez a entrada, quem costurou, dias de produção, quantidades produzidas, histórico manual de ocorrências e data de saída
- A data de saída representa a ida ao fornecedor
- Haverá módulo de embarque com seleção de OPs, geração de embarque e consolidação de minutos embarcados por tipo e etapa
- A OP só poderá embarcar normalmente quando estiver concluída em costura
- Deve existir exceção para devolução sem produzir/não industrializada, sem gerar contadores

## 9. Próximas definições necessárias
- Se haverá controle de turno
- Se haverá histórico completo de múltiplas ocorrências por OP
- O que o perfil Resultados pode visualizar/exportar
- Quais relatórios serão necessários no MVP
