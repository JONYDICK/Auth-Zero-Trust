FROM composer:2 AS dependencies
WORKDIR /app
COPY composer.json composer.lock ./
RUN composer install --no-dev --prefer-dist --no-interaction --optimize-autoloader

FROM php:8.2-apache
WORKDIR /var/www/html

COPY --from=dependencies /app/vendor ./vendor
COPY api.php index.html composer.json db.json ./

RUN mkdir -p /var/www/html/data \
    && cp /var/www/html/db.json /var/www/html/data/db.json \
    && chown -R www-data:www-data /var/www/html \
    && chmod 664 /var/www/html/data/db.json \
    && echo 'ServerName localhost' > /etc/apache2/conf-available/servername.conf \
    && a2enconf servername

EXPOSE 80

CMD ["apache2-foreground"]
