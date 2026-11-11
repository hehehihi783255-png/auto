FROM php:8.2-apache

# Cài extension cần thiết cho worker + WebSocket
RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl-dev libcurl4-openssl-dev curl tini \
    && docker-php-ext-install -j"$(nproc)" sockets pcntl posix \
    && apt-get purge -y --auto-remove libssl-dev libcurl4-openssl-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Apache modules
RUN a2enmod rewrite headers

# Apache long-running config (worker chạy 1h+)
RUN printf 'ServerName localhost\nTimeout 3700\nKeepAliveTimeout 3700\nServerLimit 25\nMaxRequestWorkers 25\nStartServers 5\nMinSpareServers 5\nMaxSpareServers 10\n' >> /etc/apache2/apache2.conf

# PHP config cho worker
RUN printf 'memory_limit=256M\nmax_execution_time=0\nmax_input_time=-1\ndefault_socket_timeout=60\nallow_url_fopen=On\noutput_buffering=Off\nimplicit_flush=On\ndisplay_errors=Off\nlog_errors=On\nerror_log=/proc/self/fd/2\ndate.timezone=Asia/Ho_Chi_Minh\nopcache.enable=0\n' > /usr/local/etc/php/conf.d/99-denius.ini

# Copy source
WORKDIR /var/www/html
COPY index.php /var/www/html/index.php

# Tạo thư mục data
RUN mkdir -p /var/www/html/.data/by_key \
    && chown -R www-data:www-data /var/www/html \
    && chmod -R 750 /var/www/html/.data \
    && chmod 644 /var/www/html/index.php

# Sinh entrypoint NGAY TRONG image (không cần file ngoài)
RUN printf '%s\n' \
    '#!/bin/bash' \
    'set -e' \
    'PORT="${PORT:-80}"' \
    'echo "[denius] Starting on port ${PORT}"' \
    'sed -i "s/^Listen 80$/Listen ${PORT}/" /etc/apache2/ports.conf' \
    'sed -i "s/<VirtualHost \\*:80>/<VirtualHost *:${PORT}>/" /etc/apache2/sites-available/000-default.conf' \
    'mkdir -p /var/www/html/.data/by_key' \
    'chown -R www-data:www-data /var/www/html/.data 2>/dev/null || true' \
    'exec apache2-foreground' \
    > /usr/local/bin/docker-entrypoint.sh \
    && chmod +x /usr/local/bin/docker-entrypoint.sh

ENV PORT=80
EXPOSE 80

HEALTHCHECK --interval=60s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/index.php?action=keepalive" || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]
