# Requisitos Funcionais - App Controle de OPs

## 1. Cadastro de OPs
Ao cadastrar uma OP, o sistema deve permitir registrar:

- Código de barras da OP (identificação rápida para movimentação)
- Número da OP
- Produto
- Flag/tipo da OP:
  - Produção
  - Mostruário
- Marca
- Quantidade total de peças
- Minutos F21
- Minutos F22
- Configuração da F23:
  - Interno
  - Externo
- Minutos F23
- Data de entrada
  - preenchimento automático com a data do lançamento
- Observações

### Regra de negócio - F23
- Se F23 for marcada como **interno**, o campo **Minutos F23** deve ser obrigatório.
- Se F23 for marcada como **externo**, o campo **Minutos F23** pode ficar desabilitado/não obrigatório.

## 2. Lançamento diário
No lançamento diário, o sistema deve permitir registrar:

- Colaborador (por código de registro)
- OP
- Quantidade produzida
- Data

### Regra do lançamento diário
- O cálculo usará **somente os minutos de F21**.
- Portanto, não será necessário campo de fase (F21/F22/F23) no MVP.

## 3. Regra de cálculo da eficiência do colaborador
O colaborador trabalha com uma base diária de minutos disponíveis para produção.

### Base padrão informada
- Minutos de trabalho por dia: **528 minutos**
- Os 528 minutos são **fixos para todos os colaboradores** no MVP.

### Forma de cálculo
Durante o dia, o colaborador pode trabalhar em mais de uma OP.
Cada OP gera minutos produzidos conforme:

**minutos produzidos da OP = quantidade produzida × minutos da fase correspondente**

Depois, somam-se os minutos produzidos de todas as OPs do dia.

**resultado diário do colaborador = minutos produzidos no dia / minutos disponíveis no dia**

### Exemplo informado
- Base diária do colaborador: **528 minutos**
- OP 1:
  - 3 peças
  - F21 = 7,45
  - minutos produzidos = 3 × 7,45 = **22,35**
- OP 2:
  - 17 peças
  - F21 = 9,37
  - minutos produzidos = 17 × 9,37 = **159,29**

**Total de minutos produzidos no dia:**
- 22,35 + 159,29 = **181,64**

**Resultado diário:**
- 181,64 / 528 = **34,40%**

## 4. Status das OPs
As OPs terão status visuais/operacionais:

- **Verde**
  - ainda interno para produzir
- **Amarelo**
  - possui pendência ou ocorrência
  - parada na empresa aguardando retorno
  - deve permitir registro em texto
  - quando houver retorno, a ocorrência pode ser marcada como concluída com justificativa de finalização
  - após conclusão, a OP volta para status verde
- **Azul**
  - concluída em costura
  - atingiu a quantidade total cadastrada da OP
- **Vermelho**
  - já embarcou para fornecedor

## 5. Regra de controle de quantidade da OP
O sistema deve acompanhar a quantidade produzida acumulada por OP.

### Comportamentos esperados
- Informar se a quantidade lançada ainda está abaixo do total previsto
- Informar quando faltar quantidade para concluir a OP
- Informar se o lançamento ultrapassa a quantidade limite cadastrada
- Quando a quantidade total da OP for atingida, a OP deve mudar para status **Azul** (concluída em costura)

## 6. Consulta detalhada da OP
A tela de consulta de informações da OP deve mostrar os dados completos da ordem.

### A consulta da OP deve exibir
- Todos os dados cadastrais da OP
- Todo o histórico da OP
- Data de entrada
- Quem fez a entrada
- Quem costurou
- Dia em que costurou
- Quantidade de peças produzidas por lançamento
- Histórico de ocorrências informadas manualmente
- Data de saída da OP

### Regra da data de saída
- A data de saída da OP é a data em que ela vai ao fornecedor.

## 7. Histórico da OP
Cada OP deve ter um histórico detalhado de produção.

### O histórico deve registrar
- Qual colaborador produziu
- Qual quantidade esse colaborador produziu
- Em quais dias houve produção da OP

### Origem dessas informações
O histórico da OP será alimentado pelos lançamentos diários.
Cada lançamento deve ficar vinculado à OP e ao colaborador correspondente.

## 8. Módulo de embarque
Deve existir um módulo específico para embarque de OPs.

### Funcionalidades do módulo de embarque
- Selecionar OPs para embarque por flag
- Ter opção de busca para localizar OPs e marcar seleção
- Após selecionar todas as OPs do dia, permitir a ação **Gerar embarque**

### Ao gerar embarque, o sistema deve consolidar
- Minutos embarcados de **Mostruário**
- Minutos embarcados de **Produção**
- Minutos embarcados de **F21 + F22** (costura)
- Minutos embarcados de **F23** (pós-costura)

### Resultados esperados do embarque
- Registrar a data de saída/embarque da OP
- Permitir relatório do que foi embarcado por:
  - dia
  - semana
  - mês operacional

### Regra de embarque
- A OP só pode embarcar quando todas as peças tiverem sido costuradas/produzidas.
- Em termos práticos, o embarque normal só pode ocorrer quando a OP já estiver concluída em costura.

### Exceção: devolução sem produção
- Se a OP não for produzida, deve existir uma justificativa de devolução sem produzir / não industrializada.
- Nessa situação, a OP não deve gerar contadores de produção.
- Essa devolução deve ficar registrada no histórico da OP.

## 9. Dashboard inicial
A tela principal deve apresentar:

- Totais produzidos
- Totais a produzir
- Resultado da empresa por período
- Resultado por colaborador
- Filtros:
  - dia
  - semana
  - mês operacional

## 6. Regra de período mensal
O mês operacional da empresa é contado:

- do dia **26** de um mês
- até o dia **25** do mês seguinte
