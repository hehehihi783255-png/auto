#!/bin/bash
# ═══════════════════════════════════════════════════════════
#  Entrypoint: bind Apache lên $PORT (Render inject)
# ═══════════════════════════════════════════════════════════
set -e

PORT="${PORT:-80}"

echo "[denius] ─────────────────────────────────────"
echo "[denius] DENIUS AUTO — ONIICHAN SUPREME"
echo "[denius] Version: 3.0.0"
echo "[denius] Port: ${PORT}"
echo "[denius] PHP: $(php -v | head -1)"
echo "[denius] Extensions: sockets, pcntl, posix"
echo "[denius] ─────────────────────────────────────"

# Bind Apache lên đúng port Render yêu cầu
sed -i "s/^Listen 80$/Listen ${PORT}/" /etc/apache2/ports.conf
sed -i "s/<VirtualHost \*:80>/<VirtualHost *:${PORT}>/" /etc/apache2/sites-available/000-default.conf

# Đảm bảo thư mục .data tồn tại (trường hợp mount volume)
mkdir -p /var/www/html/.data/by_key
chown -R www-data:www-data /var/www/html/.data 2>/dev/null || true

# Kiểm tra chống lỗi cấu hình
apache2ctl configtest 2>&1 | sed 's/^/[denius] /'

echo "[denius] Starting Apache..."

# Chạy Apache foreground (tini đã lo signal)
exec apache2-foreground
