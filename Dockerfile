
FROM php:8.2-apache

WORKDIR /var/www/html

RUN docker-php-ext-install opcache

COPY index.php /var/www/html/index.php

RUN chown -R www-data:www-data /var/www/html \
    && chmod 644 /var/www/html/index.php

EXPOSE 80

CMD ["apache2-foreground"]
