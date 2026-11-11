FROM php:8.2-apache

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl-dev libcurl4-openssl-dev curl tini \
    && docker-php-ext-install -j"$(nproc)" sockets pcntl posix \
    && apt-get purge -y --auto-remove libssl-dev libcurl4-openssl-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN a2enmod rewrite headers

RUN printf 'ServerName localhost\nTimeout 3700\nKeepAliveTimeout 3700\n' >> /etc/apache2/apache2.conf

RUN printf 'memory_limit=256M\nmax_execution_time=0\ndefault_socket_timeout=60\nallow_url_fopen=On\ndisplay_errors=Off\nlog_errors=On\nerror_log=/proc/self/fd/2\ndate.timezone=Asia/Ho_Chi_Minh\nopcache.enable=0\n' > /usr/local/etc/php/conf.d/99-denius.ini

WORKDIR /var/www/html
COPY index.php /var/www/html/index.php

RUN mkdir -p /var/www/html/.data/by_key \
    && chown -R www-data:www-data /var/www/html \
    && chmod -R 750 /var/www/html/.data \
    && chmod 644 /var/www/html/index.php

RUN printf '%s\n' \
    '#!/bin/bash' \
    'set -e' \
    'PORT="${PORT:-80}"' \
    'sed -i "s/^Listen 80$/Listen ${PORT}/" /etc/apache2/ports.conf' \
    'sed -i "s/<VirtualHost \\*:80>/<VirtualHost *:${PORT}>/" /etc/apache2/sites-available/000-default.conf' \
    'mkdir -p /var/www/html/.data/by_key' \
    'chown -R www-data:www-data /var/www/html/.data 2>/dev/null || true' \
    'exec apache2-foreground' \
    > /usr/local/bin/docker-entrypoint.sh \
    && chmod +x /usr/local/bin/docker-entrypoint.sh

ENV PORT=80
EXPOSE 80

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]
