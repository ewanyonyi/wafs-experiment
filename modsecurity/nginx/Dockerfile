FROM debian:bookworm-slim

# Install Nginx and ModSecurity dependencies
RUN apt-get update && apt-get install -y \
    nginx \
    libmodsecurity3 \
    libnginx-mod-http-ndk \
    libnginx-mod-http-modsecurity \
    && rm -rf /var/lib/apt/lists/*

# Copy ModSecurity configurations
COPY nginx.conf /etc/nginx/nginx.conf
COPY modsecurity.conf /etc/nginx/modsecurity.conf
COPY crs-setup.conf /etc/nginx/crs-setup.conf
COPY rules/ /etc/nginx/rules/

# Enable ModSecurity module
RUN echo "load_module modules/ngx_http_modsecurity_module.so;" > /etc/nginx/modules.conf

# Expose Nginx HTTP port
EXPOSE 80

# Start Nginx in foreground mode
CMD ["nginx", "-g", "daemon off;"]
