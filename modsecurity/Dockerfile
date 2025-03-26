FROM nginx:alpine

# Install build dependencies
RUN apk update && \
    apk add --no-cache --virtual .build-deps \
    gcc musl-dev linux-headers pcre-dev zlib-dev make git curl automake autoconf libtool g++

# Download and compile ModSecurity
RUN git clone --depth 1 -b v3/master https://github.com/owasp-modsecurity/ModSecurity.git /usr/src/modsecurity && \
    cd /usr/src/modsecurity && \
    git submodule init && \
    (git submodule update --depth 1 || true) && \
    ./build.sh && \
    ./configure --with-nginx-module && \
    make -j$(nproc) && \
    make install

# Configure Nginx with ModSecurity
RUN echo "load_module /usr/local/nginx/modules/ngx_http_modsecurity_module.so;" >> /etc/nginx/nginx.conf

# Copy configuration files
COPY nginx.conf /etc/nginx/nginx.conf
COPY modsecurity.conf /etc/nginx/modsecurity.conf
COPY owasp-crs /etc/nginx/owasp-crs
COPY bWAPP /var/www/html/bWAPP

# Clean up build dependencies
RUN apk del .build-deps && rm -rf /usr/src/modsecurity