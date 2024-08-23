SELECT 'CREATE DATABASE ids_db' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'ids_db')\gexec
GRANT ALL PRIVILEGES ON DATABASE ids_db TO ids_user;
