#!/bin/sh
# Must use Unix (LF) line endings. Runs in Linux container; DB_* for Docker set below.
set -u
cd /var/www/html

echo "[gameloft-backend] composer install (first run can take several minutes)..."
set +e
composer install --no-interaction --no-progress
composer_exit=$?
set -e
if [ "$composer_exit" -ne 0 ]; then
  echo "[gameloft-backend] ERROR: composer install failed (exit $composer_exit). See logs above."
  exit "$composer_exit"
fi

mkdir -p storage/framework/sessions storage/framework/views storage/framework/cache storage/logs bootstrap/cache
chmod -R a+rwX storage bootstrap/cache 2>/dev/null || true

if [ -f /.dockerenv ]; then
  export DB_CONNECTION=mysql
  export DB_HOST=mysql
  export DB_PORT=3306
  echo "[gameloft-backend] Docker: DB_HOST=${DB_HOST} DB_PORT=${DB_PORT}"
fi

echo "[gameloft-backend] clearing Laravel caches..."
php artisan optimize:clear 2>/dev/null || true

echo "[gameloft-backend] starting php artisan serve on 0.0.0.0:8000"
exec php artisan serve --host=0.0.0.0 --port=8000
