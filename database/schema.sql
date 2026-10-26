PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  full_name TEXT NOT NULL,
  password_hash TEXT,
  role TEXT NOT NULL CHECK (role IN ('adm', 'operacional', 'resultados', 'apontamento', 'lancador')),
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS employees (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  registration_code TEXT NOT NULL UNIQUE,
  full_name TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1,
  start_date TEXT,
  termination_date TEXT,
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS brands (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS collections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS app_settings (
  key TEXT PRIMARY KEY,
  value TEXT,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ops (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  barcode TEXT UNIQUE,
  op_number TEXT NOT NULL UNIQUE,
  product_name TEXT NOT NULL,
  op_type TEXT NOT NULL CHECK (op_type IN ('producao', 'mostruario')),
  brand TEXT,
  collection_name TEXT,
  pilot_mode TEXT,
  appliance TEXT,
  total_pieces INTEGER NOT NULL CHECK (total_pieces > 0),
  minutes_f21 REAL NOT NULL CHECK (minutes_f21 >= 0),
  minutes_f22 REAL NOT NULL DEFAULT 0 CHECK (minutes_f22 >= 0),
  f23_mode TEXT NOT NULL CHECK (f23_mode IN ('interno', 'externo')),
  minutes_f23 REAL,
  entry_date TEXT NOT NULL DEFAULT (date('now', '-3 hours')),
  entered_by_user_id INTEGER REFERENCES users(id),
  notes TEXT,
  status_color TEXT NOT NULL DEFAULT 'verde' CHECK (status_color IN ('verde', 'amarelo', 'azul', 'rosa', 'vermelho')),
  lifecycle_type TEXT NOT NULL DEFAULT 'normal' CHECK (lifecycle_type IN ('normal', 'devolvida_sem_producao', 'nao_industrializada')),
  shipped_at TEXT,
  is_billed INTEGER NOT NULL DEFAULT 0,
  billed_at TEXT,
  billing_notes TEXT,
  billed_by_user_id INTEGER REFERENCES users(id),
  returned_without_production_at TEXT,
  return_reason TEXT,
  is_reversed INTEGER NOT NULL DEFAULT 0,
  reversed_at TEXT,
  reversed_reason TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CHECK ((f23_mode = 'interno' AND minutes_f23 IS NOT NULL) OR f23_mode = 'externo')
);

CREATE TABLE IF NOT EXISTS op_daily_productions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  op_id INTEGER NOT NULL REFERENCES ops(id) ON DELETE CASCADE,
  employee_id INTEGER NOT NULL REFERENCES employees(id),
  production_date TEXT NOT NULL,
  produced_quantity INTEGER NOT NULL CHECK (produced_quantity > 0),
  used_minutes_f21 REAL NOT NULL,
  normal_minutes REAL NOT NULL DEFAULT 0,
  extra_minutes REAL NOT NULL DEFAULT 0,
  produced_minutes REAL NOT NULL,
  extra_time_id INTEGER REFERENCES op_extra_times(id),
  extra_reason_snapshot TEXT,
  extra_description_snapshot TEXT,
  extra_effective_date_snapshot TEXT,
  extra_minutes_per_piece_snapshot REAL,
  created_by_user_id INTEGER REFERENCES users(id),
  is_reversed INTEGER NOT NULL DEFAULT 0,
  reversed_at TEXT,
  reversed_reason TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS hourly_productions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  op_id INTEGER NOT NULL REFERENCES ops(id) ON DELETE CASCADE,
  employee_id INTEGER NOT NULL REFERENCES employees(id),
  production_date TEXT NOT NULL,
  hour_slot TEXT NOT NULL,
  produced_quantity INTEGER NOT NULL CHECK (produced_quantity > 0),
  used_minutes_f21 REAL NOT NULL,
  normal_minutes REAL NOT NULL DEFAULT 0,
  extra_minutes REAL NOT NULL DEFAULT 0,
  produced_minutes REAL NOT NULL,
  extra_time_id INTEGER REFERENCES op_extra_times(id),
  extra_reason_snapshot TEXT,
  extra_description_snapshot TEXT,
  extra_effective_date_snapshot TEXT,
  extra_minutes_per_piece_snapshot REAL,
  notes TEXT,
  created_by_user_id INTEGER REFERENCES users(id),
  is_validated INTEGER NOT NULL DEFAULT 0,
  validated_at TEXT,
  validated_daily_production_id INTEGER REFERENCES op_daily_productions(id),
  validated_by_user_id INTEGER REFERENCES users(id),
  is_reversed INTEGER NOT NULL DEFAULT 0,
  reversed_at TEXT,
  reversed_reason TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_hourly_productions_unique_active ON hourly_productions (employee_id, production_date, hour_slot) WHERE is_reversed = 0;

CREATE TABLE IF NOT EXISTS op_extra_times (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  op_id INTEGER NOT NULL REFERENCES ops(id) ON DELETE CASCADE,
  extra_minutes_per_piece REAL NOT NULL CHECK (extra_minutes_per_piece >= 0),
  reason TEXT NOT NULL,
  description TEXT,
  effective_date TEXT NOT NULL,
  notes TEXT,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_by_user_id INTEGER REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS op_occurrences (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  op_id INTEGER NOT NULL REFERENCES ops(id) ON DELETE CASCADE,
  description TEXT NOT NULL,
  opened_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  opened_by_user_id INTEGER REFERENCES users(id),
  is_concluded INTEGER NOT NULL DEFAULT 0,
  concluded_at TEXT,
  conclusion_reason TEXT,
  concluded_by_user_id INTEGER REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS op_problem_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  op_id INTEGER NOT NULL REFERENCES ops(id) ON DELETE CASCADE,
  problem_date TEXT NOT NULL DEFAULT (date('now', '-3 hours')),
  quantity INTEGER NOT NULL CHECK (quantity > 0),
  reason TEXT NOT NULL,
  notes TEXT,
  created_by_user_id INTEGER REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS employee_absences (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  employee_id INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
  absence_date TEXT NOT NULL,
  absence_type TEXT NOT NULL CHECK (absence_type IN ('falta', 'atestado', 'ferias', 'folga', 'afastamento', 'outro')),
  justification TEXT NOT NULL,
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (employee_id, absence_date)
);

CREATE TABLE IF NOT EXISTS employee_daily_closures (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  employee_id INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
  work_date TEXT NOT NULL,
  status_type TEXT NOT NULL CHECK (status_type IN ('sem_lancamento_justificado', 'folga', 'feriado', 'treinamento', 'apoio_externo', 'afastamento', 'outro')),
  justification TEXT NOT NULL,
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (employee_id, work_date)
);

CREATE TABLE IF NOT EXISTS shipments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  shipment_number TEXT NOT NULL UNIQUE,
  shipment_date TEXT NOT NULL,
  notes TEXT,
  total_ops INTEGER NOT NULL DEFAULT 0,
  production_minutes REAL NOT NULL DEFAULT 0,
  sample_minutes REAL NOT NULL DEFAULT 0,
  sewing_minutes REAL NOT NULL DEFAULT 0,
  post_sewing_minutes REAL NOT NULL DEFAULT 0,
  total_minutes REAL NOT NULL DEFAULT 0,
  is_reversed INTEGER NOT NULL DEFAULT 0,
  reversed_at TEXT,
  reversed_reason TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS shipment_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  shipment_id INTEGER NOT NULL REFERENCES shipments(id) ON DELETE CASCADE,
  op_id INTEGER NOT NULL REFERENCES ops(id),
  op_number TEXT NOT NULL,
  op_type TEXT NOT NULL CHECK (op_type IN ('producao', 'mostruario')),
  total_pieces INTEGER NOT NULL,
  sewing_minutes REAL NOT NULL DEFAULT 0,
  post_sewing_minutes REAL NOT NULL DEFAULT 0,
  total_minutes REAL NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (shipment_id, op_id)
);


CREATE TABLE IF NOT EXISTS sewing_cells (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  is_active INTEGER NOT NULL DEFAULT 1,
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS op_cell_transfers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  op_id INTEGER NOT NULL REFERENCES ops(id) ON DELETE CASCADE,
  cell_id INTEGER NOT NULL REFERENCES sewing_cells(id),
  quantity_sent INTEGER NOT NULL CHECK (quantity_sent > 0),
  quantity_returned INTEGER NOT NULL DEFAULT 0 CHECK (quantity_returned >= 0),
  sent_at TEXT NOT NULL,
  sent_notes TEXT,
  returned_at TEXT,
  return_notes TEXT,
  created_by_user_id INTEGER REFERENCES users(id),
  returned_by_user_id INTEGER REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CHECK (quantity_returned <= quantity_sent)
);

CREATE TABLE IF NOT EXISTS cell_closures (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  start_date TEXT NOT NULL,
  end_date TEXT NOT NULL,
  cell_id INTEGER NOT NULL REFERENCES sewing_cells(id),
  supplier_rate_per_minute REAL NOT NULL DEFAULT 0 CHECK (supplier_rate_per_minute >= 0),
  cell_rate_per_minute REAL NOT NULL DEFAULT 0 CHECK (cell_rate_per_minute >= 0),
  notes TEXT,
  total_ops INTEGER NOT NULL DEFAULT 0,
  total_pieces INTEGER NOT NULL DEFAULT 0,
  total_minutes REAL NOT NULL DEFAULT 0,
  total_received_amount REAL NOT NULL DEFAULT 0,
  total_paid_amount REAL NOT NULL DEFAULT 0,
  total_profit_amount REAL NOT NULL DEFAULT 0,
  created_by_user_id INTEGER REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cell_closure_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  closure_id INTEGER NOT NULL REFERENCES cell_closures(id) ON DELETE CASCADE,
  op_id INTEGER NOT NULL REFERENCES ops(id),
  op_number TEXT NOT NULL,
  product_name TEXT NOT NULL,
  brand TEXT,
  total_pieces INTEGER NOT NULL DEFAULT 0,
  minutes_per_piece REAL NOT NULL DEFAULT 0,
  total_minutes REAL NOT NULL DEFAULT 0,
  supplier_rate_per_minute REAL NOT NULL DEFAULT 0,
  cell_rate_per_minute REAL NOT NULL DEFAULT 0,
  received_amount REAL NOT NULL DEFAULT 0,
  paid_amount REAL NOT NULL DEFAULT 0,
  profit_amount REAL NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (closure_id, op_id)
);

CREATE TABLE IF NOT EXISTS reversal_audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target_type TEXT NOT NULL CHECK (target_type IN ('op', 'production', 'shipment')),
  target_id INTEGER NOT NULL,
  action_type TEXT NOT NULL CHECK (action_type IN ('estorno', 'correcao')),
  reason TEXT NOT NULL,
  before_json TEXT,
  after_json TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS op_billing_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  op_id INTEGER NOT NULL REFERENCES ops(id) ON DELETE CASCADE,
  billed_at TEXT NOT NULL,
  notes TEXT,
  batch_reference TEXT,
  created_by_user_id INTEGER REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE VIEW IF NOT EXISTS v_op_production_summary AS
SELECT
  o.id AS op_id,
  o.op_number,
  o.total_pieces,
  COALESCE(SUM(p.produced_quantity), 0) AS total_produced_quantity,
  o.total_pieces - COALESCE(SUM(p.produced_quantity), 0) AS remaining_quantity,
  COALESCE(SUM(p.produced_minutes), 0) AS total_produced_minutes
FROM ops o
LEFT JOIN op_daily_productions p ON p.op_id = o.id AND p.is_reversed = 0
WHERE o.is_reversed = 0
GROUP BY o.id, o.op_number, o.total_pieces;

DROP VIEW IF EXISTS v_employee_daily_result;
CREATE VIEW v_employee_daily_result AS
SELECT
  p.employee_id,
  e.registration_code,
  e.full_name,
  e.start_date,
  e.termination_date,
  p.production_date,
  ROUND(SUM(p.produced_minutes), 2) AS produced_minutes_day,
  528.0 AS available_minutes_day,
  ROUND((SUM(p.produced_minutes) / 528.0) * 100, 2) AS result_percent_day
FROM op_daily_productions p
JOIN employees e ON e.id = p.employee_id
WHERE p.is_reversed = 0
GROUP BY p.employee_id, e.registration_code, e.full_name, e.start_date, e.termination_date, p.production_date;
