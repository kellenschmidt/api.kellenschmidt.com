# docker build -t kellenschmidt/kspw-slimphp .
# docker run --env-file ./kspw-slimphp.env -p 80:80 -d kellenschmidt/kspw-slimphp

FROM php:7-apache

RUN mkdir /slim-api
WORKDIR /slim-api

RUN apt-get update -y -qq && apt-get install -y -qq git wget zip unzip nano && apt-get -qq autoclean && \
    docker-php-ext-install pdo pdo_mysql mysqli

COPY composer.json ./composer.json
COPY composer.lock ./composer.lock
COPY install_composer.sh ./install_composer.sh
RUN sh install_composer.sh && php composer.phar install --optimize-autoloader --no-suggest && rm composer.phar

COPY public /var/www/html
COPY src /var/www/src
COPY templates /var/www/templates
RUN mv vendor /var/www/vendor
ADD apache2.conf /etc/apache2

EXPOSE 80
RUN a2enmod rewrite && \
    service apache2 restart
