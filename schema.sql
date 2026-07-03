CREATE TABLE IF NOT EXISTS addresses (
  token TEXT PRIMARY KEY,
  address TEXT UNIQUE
);

CREATE TABLE IF NOT EXISTS mails (
  id TEXT PRIMARY KEY,
  address TEXT,
  from_addr TEXT,
  subject TEXT,
  body TEXT,
  received_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_mails_address ON mails(address);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  expires INTEGER
);

CREATE TABLE IF NOT EXISTS rate_limits (
  key TEXT PRIMARY KEY,
  count INTEGER,
  expires INTEGER
);
