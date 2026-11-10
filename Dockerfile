
FROM php:8.2-apache

WORKDIR /var/www/html

COPY index.php /var/www/html/index.php

RUN chown -R www-data:www-data /var/www/html

EXPOSE 80
