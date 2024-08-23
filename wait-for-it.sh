#!/bin/sh
# wait-for-it.sh

set -e

host="$1"
shift
cmd="$@"

until pg_isready -h "$host" -U "$DB_USER"; do
  >&2 echo "Postgres is unavailable - sleeping"
  sleep 1
done

>&2 echo "Postgres is up - executing command"
exec $cmd
