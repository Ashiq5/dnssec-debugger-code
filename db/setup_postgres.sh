#!/bin/bash
# === Automated PostgreSQL setup script ===
# Creates database, user, and initial table schema

DB_NAME=${DB_NAME}
DB_USER=${DB_USER}
DB_PASS=${DB_PASS}

echo "=== Setting up PostgreSQL database and user ==="
sudo -u postgres psql <<EOF
DO
\$do\$
BEGIN
   IF NOT EXISTS (
      SELECT FROM pg_catalog.pg_roles WHERE rolname = '$DB_USER'
   ) THEN
      CREATE ROLE $DB_USER WITH LOGIN PASSWORD '$DB_PASS';
   END IF;
END
\$do\$;

CREATE DATABASE $DB_NAME OWNER $DB_USER;
GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;
EOF

echo "=== Creating initial table schema ==="
sudo -u postgres psql -d $DB_NAME <<EOF
CREATE TABLE IF NOT EXISTS requests (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) NOT NULL,
    instr_w_zrep TEXT,
    instr_wo_zrep TEXT,
    explanations TEXT,
    exception_msg TEXT,
    job_id UUID UNIQUE,
    status VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO $DB_USER;
EOF

echo "=== PostgreSQL setup completed successfully ==="
