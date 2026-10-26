# AgilFac

_App interno de controle de OPs, resultados e operação._

MVP funcional inicial em **Node.js + SQLite** para testes reais do fluxo de controle de OPs.

## O que já funciona

- Dashboard com filtros por:
  - tipo (Produção / Mostruário)
  - marca
  - dia
  - semana
  - mês operacional (26 até 25)
- Dashboard com totais de minutos de costura (F21 + F22), incluindo verdes, amarelos, azuis, vermelhos e agora também o bloco rosa das OPs em célula
- Resultado por colaborador considerando apenas os dias ativos no período filtrado (`dias ativos × 528`)
- Totalizador geral da empresa considerando somente operadores ativos e seus dias ativos no período
- Módulo Cadastros, exclusivo para Administrador, com base inicial de Marcas, Coleções, Células de costura (ativo/inativo) e configuração simples do nome da empresa para etiquetas
- Cadastro de OPs com autocomplete/sugestão de marcas e coleções cadastradas, além dos novos campos de Piloto e Aparelho
- Cadastro de colaboradores com datas de início e rescisão
- Lançamento diário de produção
- Opção de lançamento sequencial rápido com OP digitada manualmente, Enter para avançar e manutenção opcional do colaborador entre lançamentos, agora com aviso explícito quando a OP estiver em célula
- Módulo **Costura em célula** com envio/retorno de OP, status rosa enquanto estiver na célula, destaque nas telas principais e relatório consolidado por período/célula/tipo de OP
- Módulo de fechamento + relatórios com visão diária, semanal, mensal operacional, geral e individual por colaborador
- Fechamento com colaboradores ativos no período, dias úteis sem lançamento, justificativa manual e marcação de ausência por dia/colaborador
- Relatórios básicos do fechamento com resumo por colaborador, resumo diário, ranking de eficiência e versão para impressão/salvar em PDF pelo navegador
- Novo módulo **Prêmio de produção** com tela própria, cálculo por período (mês operacional por padrão), relatório por colaboradora e versão de impressão/PDF
- Novo módulo **Acompanhamento diário de resultado** com tela própria e bloco-resumo no dashboard, mostrando minutos acumulados e percentual atual por colaboradora no mês operacional
- Consulta de OPs com filtro por busca/status, marca, coleção e agora também por cobradas / não cobradas, incluindo botão para gerar etiquetas de entrada em HTML/impressão com base na lista filtrada
- Tela própria de etiquetas de entrada e de embarque com consulta direta, filtro por data de entrada e número da OP, além de ação individual por etiqueta
- Consulta detalhada da OP com:
  - dados cadastrais
  - quantidade produzida acumulada
  - saldo restante
  - histórico de lançamentos
  - ocorrências manuais simples
  - histórico de embarque da OP
- Novo módulo **Conciliação de cobrança** com:
  - tela própria para colar/listar OPs cobradas em lote
  - validação das OPs informadas antes de marcar
  - marcação de cobrança com data e observação opcional
  - histórico simples em `op_billing_history`
  - exibição da cobrança na consulta e no detalhe da OP
- Módulo de embarque com:
  - lista de OPs aptas (somente status azul e ainda não embarcadas)
  - busca por OP/produto/marca/código de barras
  - seleção por checkbox
  - geração do embarque com persistência em `shipments` e `shipment_items`
  - consolidação de minutos por tipo (produção / mostruário)
  - consolidação de minutos por etapa (costura = F21+F22 / pós-costura = F23)
  - atualização automática da data de saída da OP e mudança de status para vermelho
- Visualização ágil de etiquetas:
  - etiquetas de entrada via `/labels/entry`, com visualização de todas, filtro por número da OP e data de entrada, geração individual e impressão em lote do resultado filtrado
  - etiquetas de embarque via `/labels/shipment`, com visualização de todas as OPs aptas, filtro por número da OP e data de entrada, geração individual e impressão em lote do resultado filtrado
  - etiquetas também seguem disponíveis a partir da seleção em `/shipments/new` e por embarque salvo em `/shipments/:id/labels`
  - saída em HTML pronta para impressão/exportação em PDF pelo navegador
- Consulta de embarques com filtro básico por data e busca por número/OP
- Módulo enxuto de **Estornos / Correções**, exclusivo para Administrador, com:
  - busca simples por tipo de registro (`cadastro de OP`, `lançamento diário` e `embarque`)
  - ação de **corrigir** dados principais diretamente na tela
  - ação de **estornar** com motivo obrigatório
  - histórico/auditoria básica em `reversal_audit_log`
  - exclusão lógica (`is_reversed`) para não apagar rastros nem quebrar histórico
- Banco SQLite criado automaticamente na primeira execução
- Seed inicial com alguns colaboradores, OPs e lançamentos para facilitar teste

## Regras implementadas neste MVP

- OP nova inicia com status **verde**
- Quando a OP é enviada para célula, passa para status **rosa** até o retorno ser registrado
- No cadastro da OP, F23 vem **interno** por padrão; se necessário, o usuário altera para externo
- Cálculo de produção usa **somente F21**
- Base fixa diária de **528 minutos**
- No dashboard, o resultado individual usa **dias ativos no período × 528**; se `start_date` e `termination_date` estiverem vazios, o colaborador é tratado como ativo em todo o período
- O módulo **Prêmio de produção** usa a mesma base de dias úteis/feriados do fechamento para calcular a meta de 60% do período por colaboradora
- O módulo **Acompanhamento diário de resultado** usa como padrão o período operacional de **26 até 25** e calcula o **% atual** sobre os dias úteis já decorridos no período
- Quando a produção acumulada atinge a quantidade total da OP, o status vira **azul**
- O sistema bloqueia lançamentos que ultrapassem a quantidade total da OP
- Se houver ocorrência em aberto, a OP fica **amarela** enquanto não estiver concluída
- Embarque normal só aceita OP **azul** e ainda não embarcada
- Enquanto a OP estiver em célula, o lançamento diário normal fica bloqueado e ela sai do fluxo operacional comum até o retorno
- Ao gerar embarque, a OP recebe `shipped_at` e o status vira **vermelho**
- Minutos consolidados do embarque:
  - **costura** = quantidade total × (F21 + F22)
  - **pós-costura** = quantidade total × F23, somente quando F23 for interno
  - **produção / mostruário** = soma total dos minutos embarcados por tipo da OP
- Estrutura segue simples para facilitar evolução de devolução sem produção, usuários/permissões e outras regras futuras
- A base de marcas é centralizada em `brands`; a OP só aceita marca previamente cadastrada
- A base de coleções é centralizada em `collections`; quando informada na OP, também precisa existir previamente
- O nome do cabeçalho das etiquetas vem de `app_settings.company_name`
- Nas etiquetas, `T. costura` mostra o tempo unitário da OP e o total (`tempo × peças`); `T. Pós` faz o mesmo quando a OP tiver pós-costura interna
- Filtros por marca no dashboard e na consulta usam a base oficial de marcas cadastradas
- Estornos desta versão são lógicos: OP, lançamento e embarque recebem marcação de estorno e deixam de participar dos fluxos normais
- Correções exigem motivo obrigatório e geram trilha simples em `reversal_audit_log` com antes/depois em JSON
- Estorno de OP, nesta versão enxuta, só é permitido quando ela ainda não possui lançamento ativo nem embarque ativo vinculado

## Tecnologias

- Node.js 22+
- `node:sqlite` nativo do Node
- HTTP nativo (sem framework web)
- SQLite local em arquivo

## Como executar

Na pasta do projeto:

```bash
cd /root/.openclaw/workspace/projects/app-controle-ops
npm start
```

Ou em porta específica:

```bash
PORT=8090 npm start
```

Teste automatizado do bloco atual de célula:

```bash
npm run test:cell
```

Teste automatizado do módulo de conciliação de cobrança:

```bash
npm run test:billing
```

Depois acesse:

- `http://localhost:8090`

## Estrutura principal

- `server.js` → servidor web e regras do MVP
- `database/schema.sql` → schema SQLite, incluindo `brands`, `collections`, `app_settings`, `shipments`, `shipment_items`, flags de estorno lógico (`is_reversed`) e tabela `reversal_audit_log`
- `public/styles.css` → estilos da interface
- `data/app.sqlite` → banco gerado automaticamente

## Próxima etapa claramente testável

Sugestão para o próximo bloco com validação simples pela usuária:

1. abrir uma OP azul e enviar para célula;
2. confirmar se ela aparece rosa em **Consulta de OPs**, no bloco rosa do **Dashboard** e no alerta da tela da própria OP;
3. tentar lançar produção normal e validar o bloqueio;
4. registrar o retorno da célula e confirmar se ela sai do bloco rosa e volta ao fluxo azul.

Se quiser validar automaticamente a base técnica antes disso, rode `npm run test:cell`.

## Fluxos para testar rapidamente

### 0. Testar perfis rapidamente

No menu lateral existe um seletor **Perfil em teste**. Use-o para alternar entre:
- Administrador
- Operacional
- Resultados

O módulo **Cadastros** só aparece/libera para Administrador.

### 1. Configurar cadastros básicos

Abra `/cadastros` como Administrador e teste:
- cadastrar uma ou mais **marcas**
- cadastrar uma ou mais **coleções**
- definir o **nome da empresa** que aparecerá no topo das etiquetas

### 2. Cadastrar OP

Abra `/ops/new` e informe os dados.
A marca deve existir previamente em `/cadastros`; o campo usa sugestão/autocomplete via lista de marcas cadastradas.
A coleção também usa autocomplete pela base cadastrada. Piloto e Aparelho agora ficam gravados na OP e aparecem nas etiquetas.

### 3. Cadastrar colaborador

Abra `/employees`.

### 4. Lançar produção diária

Abra `/productions/new` e selecione colaborador + OP + quantidade.

### 4.1. Lançamento sequencial rápido

Em `/productions/new`, clique em **Abrir lançamento rápido**.
Nesse modo:
- a OP é digitada manualmente
- o campo data já abre com o dia atual
- o Enter avança entre os campos e, na quantidade, salva
- é possível marcar **Manter colaborador** para repetir vários lançamentos em sequência
- após salvar, o formulário retorna no modo rápido pronto para o próximo lançamento

### 5. Consultar OP + etiquetas de entrada

Abra `/ops` para listar todas.
Use os filtros desejados e clique em **Gerar etiquetas de entrada** para abrir a visualização HTML pronta para impressão/exportação.
Na própria tela `/labels/entry` agora também é possível ver todas as etiquetas, filtrar por **número da OP** e **data de entrada**, imprimir o lote filtrado ou abrir uma etiqueta individual.

### 6. Ver detalhe da OP

Clique em **Detalhar** em qualquer OP para abrir histórico, ocorrências e embarques da OP.

### 7. Gerar embarque + etiquetas de embarque

Abra `/shipments/new`, filtre se necessário, marque as OPs azuis aptas e clique em **Gerar embarque**.
Se quiser validar antes, use **Visualizar etiquetas de embarque** na mesma tela. Agora o embarque também aceita filtro por **número da OP** e **data de entrada**.
Na tela `/labels/shipment` dá para ver todas as OPs aptas, filtrar, imprimir o lote filtrado ou abrir uma etiqueta individual. Depois de salvar o embarque, também é possível abrir as etiquetas pelo detalhe do embarque.

### 8. Consultar embarques

Abra `/shipments` para listar embarques gerados, filtrar por período e abrir o detalhamento.

### 9. Testar Fechamento + Relatórios

Abra `/closures`.

O que já dá para testar nesta versão:
- filtros de visão por **dia, semana, mês operacional, geral** e **personalizado**
- filtro **individual por colaborador**
- lista apenas dos colaboradores ativos no período, respeitando `start_date` e `termination_date`
- identificação de dias úteis sem lançamento por colaborador
- resolução manual de cada pendência com justificativa simples
- marcação de ausência por dia/colaborador com tipo + justificativa
- troca automática entre justificativa e ausência no mesmo dia, evitando duplicidade de tratamento
- resumo por colaborador com peças, minutos, base monitorada e eficiência
- resumo diário do fechamento para leitura como diário de produção
- ranking simples de eficiência por colaborador
- botão para abrir **versão para impressão / salvar em PDF** no navegador

Observação desta versão funcional mínima: o fechamento considera dias úteis de segunda a sexta e ainda não automatiza feriados nem gera PDF nativo; a saída preparada para exportação usa a impressão do navegador.

### 10. Testar Prêmio de produção

Abra `/premios/producao`.

O que já dá para testar nesta versão:
- cálculo por **dia, semana, mês operacional, geral** e **personalizado**
- filtro **individual por colaborador/costureira**
- base de dias úteis alinhada ao fechamento, incluindo respeito aos **feriados configurados**
- relatório principal com a estrutura pedida: **nome / prêmio produção / prêmio 60% / prêmio extra**
- faixas de bonificação aplicadas automaticamente:
  - **40% = R$ 30,00**
  - **45% = R$ 60,00**
  - **50% = R$ 90,00**
  - **60% = R$ 400,00**
  - **extra = R$ 10,00** a cada 100 minutos acima da meta de 60%
- botão para abrir **versão para impressão / salvar em PDF** no navegador

### 11. Testar Estornos / Correções (ADM)

Abra `/estornos` com o perfil **Administrador**.

O que já dá para testar:
- buscar por **cadastro de OP**, **lançamento diário** ou **embarque** com pesquisa simples
- corrigir registro com **motivo obrigatório**
- estornar registro com **motivo obrigatório**
- baixar OP **sem industrialização** com motivo obrigatório tanto em `/estornos` quanto direto na **Consulta de OPs** e no detalhe da OP (atalho ADM)
- ver o reflexo do estorno no fluxo normal:
  - lançamento estornado deixa de contar no saldo e no dashboard
  - embarque estornado libera novamente a OP, removendo `shipped_at`
  - OP estornada some das listas normais (desde que não tenha vínculos ativos)
  - OP baixada sem industrialização fica azul, com saldo encerrado para a operação e apta para embarque sem minutos
- consultar o histórico das últimas ações na própria tela, alimentado por `reversal_audit_log`

## Observações importantes

- O app não depende de instalação extra de pacote SQLite.
- Os dados ficam em arquivo local SQLite.
- O MVP foi mantido simples para facilitar evolução do negócio sem travar em arquitetura pesada cedo demais.

## Próximos passos sugeridos

- Login e perfis de acesso
- Dashboard mais completo por metas/resultados
- Devolução sem produção / não industrializada
- Relatórios por período com exportação
- Cadastro de usuários e trilha de auditoria real
- Validações mais rígidas para excesso de produção
