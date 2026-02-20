#!/bin/bash
# Restore RAG database from a SQL backup file

# Database connection settings
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-raguser}"
DB_PASSWORD="${DB_PASSWORD:-ragpass}"
DB_NAME="${DB_NAME:-postgres}"

# Check if backup file is provided
if [ -z "$1" ]; then
    echo "❌ Usage: $0 <backup_file.sql>"
    echo "📂 Available backups in ./backups:"
    ls -lh ./backups/*.sql 2>/dev/null || echo "   (no backups found)"
    exit 1
fi

BACKUP_FILE="$1"

# Check if backup file exists
if [ ! -f "$BACKUP_FILE" ]; then
    echo "❌ Backup file not found: $BACKUP_FILE"
    exit 1
fi

echo "🔄 Restoring database '$DB_NAME' from $BACKUP_FILE..."

# Confirm before proceeding
read -p "⚠️  This will DROP and recreate existing tables. Continue? (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
    echo "❌ Restore cancelled."
    exit 0
fi

# Set PGPASSWORD environment variable for psql
export PGPASSWORD="$DB_PASSWORD"

# Restore the database
psql -h "$DB_HOST" \
     -p "$DB_PORT" \
     -U "$DB_USER" \
     -d "$DB_NAME" \
     --verbose \
     < "$BACKUP_FILE"

# Check if restore was successful
if [ $? -eq 0 ]; then
    echo "✅ Restore completed successfully!"
    echo ""
    echo "📊 Database statistics:"
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "
        SELECT
            'documents' AS table_name, COUNT(*) AS row_count
        FROM documents
        UNION ALL
        SELECT
            'chunks' AS table_name, COUNT(*) AS row_count
        FROM chunks;
    "
else
    echo "❌ Restore failed!"
    exit 1
fi

# Unset password
unset PGPASSWORD
