# FROM debian:bookworm-slim

# # Install dependencies
# RUN apt-get update && apt-get install -y \
#     nginx \
#     libmodsecurity3 \
#     nginx-extras \
#     && rm -rf /var/lib/apt/lists/*

# # Copy ModSecurity configurations
# COPY nginx.conf /etc/nginx/nginx.conf
# COPY modsecurity.conf /etc/nginx/modsecurity.conf
# COPY crs-setup.conf /etc/nginx/crs-setup.conf
# COPY rules/ /etc/nginx/rules/

# # Verify that the module exists
# RUN test -f /usr/lib/nginx/modules/ngx_http_modsecurity_module.so || (echo "Module not found!" && exit 1)

# # Load ModSecurity module
# RUN echo "load_module /usr/lib/nginx/modules/ngx_http_modsecurity_module.so;" > /etc/nginx/modules-enabled/modsecurity.conf

# # Expose Nginx HTTP port
# EXPOSE 80

# # Start Nginx in foreground mode
# CMD ["nginx", "-g", "daemon off;"]

FROM owasp/modsecurity-crs:nginx

# Ensure we have permissions to modify the ModSecurity configuration
USER root

# Copy custom ModSecurity configurations
COPY nginx.conf /etc/nginx/nginx.conf
COPY modsecurity.conf /etc/modsecurity/modsecurity.conf
COPY crs-setup.conf /etc/modsecurity/crs-setup.conf
COPY rules/ /etc/modsecurity/rules/

RUN chmod 666 /etc/modsecurity/modsecurity.conf


# Ensure ModSecurity is enabled
RUN sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf

# Expose port 80
EXPOSE 80

# Start Nginx
CMD ["nginx", "-g", "daemon off;"]
