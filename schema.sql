DROP TABLE IF EXISTS audit_log CASCADE;
DROP TABLE IF EXISTS ticket_log CASCADE;
DROP TABLE IF EXISTS tickets CASCADE;
DROP TABLE IF EXISTS assets CASCADE;
DROP TABLE IF EXISTS users CASCADE;

CREATE TABLE users (
  id            SERIAL PRIMARY KEY,
  name          VARCHAR(100) NOT NULL,
  email         VARCHAR(120) NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role          VARCHAR(20) NOT NULL CHECK (role IN ('admin','technician','staff')) DEFAULT 'staff',
  last_login    TIMESTAMP,
  created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE assets (
  id           SERIAL PRIMARY KEY,
  tag          VARCHAR(50) NOT NULL UNIQUE,
  type         VARCHAR(50) NOT NULL,
  make         VARCHAR(50),
  model        VARCHAR(50),
  serial       VARCHAR(100),
  assigned_to  INTEGER REFERENCES users(id) ON DELETE SET NULL,
  location     VARCHAR(100),
  status       VARCHAR(20) NOT NULL CHECK (status IN ('in_use','in_storage','repair','retired')) DEFAULT 'in_storage',
  purchased_on DATE,
  created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE tickets (
  id          SERIAL PRIMARY KEY,
  title       VARCHAR(150) NOT NULL,
  description TEXT,
  priority    VARCHAR(20) NOT NULL CHECK (priority IN ('low','medium','high','urgent')) DEFAULT 'medium',
  status      VARCHAR(20) NOT NULL CHECK (status IN ('open','in_progress','resolved','closed')) DEFAULT 'open',
  asset_id    INTEGER REFERENCES assets(id) ON DELETE SET NULL,
  created_by  INTEGER NOT NULL REFERENCES users(id),
  assigned_to INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE ticket_log (
  id         SERIAL PRIMARY KEY,
  ticket_id  INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
  user_id    INTEGER NOT NULL REFERENCES users(id),
  note       TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE audit_log (
  id         SERIAL PRIMARY KEY,
  user_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
  action     VARCHAR(50) NOT NULL,
  details    TEXT,
  ip_address VARCHAR(45),
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);