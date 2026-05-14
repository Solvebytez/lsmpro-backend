FROM php:8.3-cli-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    unzip \
    libzip-dev \
    libpng-dev \
    libonig-dev \
    && docker-php-ext-configure zip \
    && docker-php-ext-install -j"$(nproc)" pdo_mysql mbstring zip exif pcntl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /var/www/html

ENV COMPOSER_ALLOW_SUPERUSER=1

# Outside the bind mount so Windows CRLF on ./backend cannot break boot; strip CR if build context has CRLF.
COPY docker-entrypoint.sh /usr/local/bin/gameloft-docker-entrypoint.sh
RUN sed -i 's/\r$//' /usr/local/bin/gameloft-docker-entrypoint.sh \
    && chmod +x /usr/local/bin/gameloft-docker-entrypoint.sh

ENTRYPOINT ["sh", "/usr/local/bin/gameloft-docker-entrypoint.sh"]
