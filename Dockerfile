# Security: Use patched PHP version to fix CVE-2024-4577 and updated base image for CVE-2025-68973 and CVE-2025-69420
FROM php:8.2.23-apache

# Security: Update system packages first to patch known CVEs including CVE-2025-68973 and CVE-2025-69420
# Install system dependencies and clean up in single layer
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y \
        gnupg2 \
        libssl3 \
        openssl \
        ca-certificates \
        libpng-dev \
        libjpeg62-turbo-dev \
        libfreetype6-dev \
        libwebp-dev \
        libxpm-dev \
        curl \
    && docker-php-ext-configure gd \
        --with-freetype \
        --with-jpeg \
        --with-webp \
        --with-xpm \
    && docker-php-ext-install -j$(nproc) gd \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Enable Apache mod_rewrite and security modules
RUN a2enmod rewrite headers ssl

# Security: Configure Apache with security headers and CVE-2024-4577 mitigation
RUN { \
    echo 'ServerTokens Prod'; \
    echo 'ServerSignature Off'; \
    echo 'Header always set X-Content-Type-Options nosniff'; \
    echo 'Header always set X-Frame-Options DENY'; \
    echo 'Header always set X-XSS-Protection "1; mode=block"'; \
    echo 'Header always set Referrer-Policy "strict-origin-when-cross-origin"'; \
    echo '# CVE-2024-4577 mitigation - Disable CGI if not needed'; \
    echo '<Directory "/usr/local/bin">'; \
    echo '    AllowOverride None'; \
    echo '    Require all denied'; \
    echo '</Directory>'; \
    } > /etc/apache2/conf-available/security-headers.conf \
    && a2enconf security-headers

# Create secure directories with proper ownership
RUN mkdir -p /var/www/html/temp \
    && chown -R www-data:www-data /var/www/html \
    && chmod 755 /var/www/html/temp

# Copy application files
COPY --chown=www-data:www-data *.php /var/www/html/
COPY --chown=www-data:www-data css/ /var/www/html/css/
COPY --chown=www-data:www-data js/ /var/www/html/js/

# Security: Configure PHP with secure settings including CVE-2024-4577 mitigation
RUN { \
    echo 'expose_php = Off'; \
    echo 'display_errors = Off'; \
    echo 'log_errors = On'; \
    echo 'error_log = /var/log/php_errors.log'; \
    echo 'upload_max_filesize = 5M'; \
    echo 'post_max_size = 10M'; \
    echo 'max_execution_time = 30'; \
    echo 'max_input_time = 30'; \
    echo 'memory_limit = 128M'; \
    echo 'file_uploads = On'; \
    echo 'upload_tmp_dir = /var/www/html/temp'; \
    echo 'session.cookie_secure = 1'; \
    echo 'session.cookie_httponly = 1'; \
    echo 'session.use_strict_mode = 1'; \
    echo 'allow_url_fopen = Off'; \
    echo 'allow_url_include = Off'; \
    echo '# CVE-2024-4577 mitigation'; \
    echo 'cgi.force_redirect = 1'; \
    echo 'cgi.fix_pathinfo = 0'; \
    echo 'fastcgi.logging = 0'; \
    } > /usr/local/etc/php/conf.d/security.ini

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost/ || exit 1

# Expose port
EXPOSE 80