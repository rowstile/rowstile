# The Laravel suite's PHP side (test.sh builds it, and runs Composer, PHPStan, PHPUnit, the app and its queue worker
# in it): the official PHP image and Composer's, pinned in ../images/Dockerfile (by digest, which Dependabot moves
# there), with what the SDK and the checks need: pdo_pgsql, Xdebug for coverage (lines and branches: off unless
# XDEBUG_MODE says), pcntl for the queue worker, and python3 for the rowstile command (check 14 runs rowstile
# migrate and rowstile client from the tests).
#   docker build -t rowstile-laravel --build-arg PHP_IMAGE=<php image> --build-arg COMPOSER_IMAGE=<composer image> \
#     -f integrations/laravel/php.Dockerfile integrations/laravel
ARG PHP_IMAGE
ARG COMPOSER_IMAGE
FROM ${COMPOSER_IMAGE} AS composer
FROM ${PHP_IMAGE}
RUN apk add --no-cache bash git unzip libpq python3 \
 && apk add --no-cache --virtual .build $PHPIZE_DEPS linux-headers postgresql-dev \
 && docker-php-ext-install -j"$(nproc)" pdo_pgsql pcntl \
 && pecl install xdebug-3.5.3 \
 && docker-php-ext-enable xdebug \
 && apk del .build \
 && rm -rf /tmp/pear
ENV XDEBUG_MODE=off
COPY --from=composer /usr/bin/composer /usr/bin/composer
