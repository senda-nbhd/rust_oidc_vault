#!/bin/bash

set -e
set -u

function create_user_and_database() {
    local database=$1
    local user=$2
    local password=$3
    echo "  Creating user and database '$database'"
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "postgres" <<-EOSQL
        CREATE USER $user WITH PASSWORD '$password';
        CREATE DATABASE $database;
        GRANT ALL PRIVILEGES ON DATABASE $database TO $user;
EOSQL
    
    # Connect to the new database and grant schema privileges
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$database" <<-EOSQL
        ALTER DATABASE $database OWNER TO $user;
        GRANT ALL ON SCHEMA public TO $user;
        ALTER SCHEMA public OWNER TO $user;
        GRANT ALL ON ALL TABLES IN SCHEMA public TO $user;
        GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO $user;
        GRANT ALL ON ALL FUNCTIONS IN SCHEMA public TO $user;
        ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO $user;
        ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO $user;
        ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO $user;
EOSQL
}

if [ -n "$POSTGRES_MULTIPLE_DATABASES" ]; then
    echo "Multiple database creation requested: $POSTGRES_MULTIPLE_DATABASES"
    for db in $(echo $POSTGRES_MULTIPLE_DATABASES | tr ',' ' '); do
        # Extract the database name, user, and password using : as delimiter
        IFS=':' read -r database user password <<< "$db"
        if [ -n "$database" ] && [ -n "$user" ] && [ -n "$password" ]; then
            create_user_and_database "$database" "$user" "$password"
        else
            echo "Error: Invalid database configuration format: $db"
            echo "Expected format: database:user:password"
            exit 1
        fi
    done
    echo "Multiple databases created"
fi