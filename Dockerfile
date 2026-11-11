# ═══════════════════════════════════════════════════════════
#  DENIUS AUTO — ONIICHAN SUPREME
#  Base: PHP 8.2 + Apache
#  Extensions: sockets, pcntl, posix (cần cho worker + WS)
# ═══════════════════════════════════════════════════════════
FROM php:8.2-apache

# ─── Cài đặt system deps + PHP extensions ───────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl-dev \
        libcurl4-openssl-dev \
        curl \
        tini \
    && docker-php-ext-install -j"$(nproc)" sockets pcntl posix \
    && apt-get purge -y --auto-remove libssl-dev libcurl4-openssl-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ─── Bật Apache modules cần thiết ───────────────────────────
RUN a2enmod rewrite headers

# ─── Cấu hình Apache cho long-running worker ────────────────
# Worker có thể chạy liên tục 3600s → cần timeout > 1 giờ
# Giới hạn worker để không tràn RAM 512MB của Render free tier
RUN { \
        echo 'ServerName localhost'; \
        echo 'Timeout 3700'; \
        echo 'KeepAliveTimeout 3700'; \
        echo 'ServerLimit 25'; \
        echo 'MaxRequestWorkers 25'; \
        echo 'StartServers 5'; \
        echo 'MinSpareServers 5'; \
        echo 'MaxSpareServers 10'; \
    } >> /etc/apache2/apache2.conf

# ─── Cấu hình PHP cho worker ────────────────────────────────
RUN { \
        echo 'memory_limit = 256M'; \
        echo 'max_execution_time = 0'; \
        echo 'max_input_time = -1'; \
        echo 'default_socket_timeout = 60'; \
        echo 'allow_url_fopen = On'; \
        echo 'output_buffering = Off'; \
        echo 'implicit_flush = On'; \
        echo 'display_errors = Off'; \
        echo 'log_errors = On'; \
        echo 'error_log = /proc/self/fd/2'; \
        echo 'date.timezone = Asia/Ho_Chi_Minh'; \
        echo 'opcache.enable = 0'; \
    } > /usr/local/etc/php/conf.d/99-denius.ini

# ─── Copy source ────────────────────────────────────────────
WORKDIR /var/www/html

COPY index.php /var/www/html/index.php
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# ─── Tạo thư mục .data với quyền đúng ───────────────────────
RUN mkdir -p /var/www/html/.data/by_key \
    && chown -R www-data:www-data /var/www/html \
    && chmod -R 750 /var/www/html/.data \
    && chmod 644 /var/www/html/index.php

# ─── Render sẽ inject PORT, mặc định 80 ─────────────────────
ENV PORT=80

# ─── Healthcheck (Render dùng path này) ─────────────────────
HEALTHCHECK --interval=60s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/index.php?action=keepalive" || exit 1

EXPOSE 80

# ─── Chạy qua tini để reap zombie process (worker con) ──────
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]
