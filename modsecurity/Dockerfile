FROM nginx:alpine

RUN apk add --no-cache modsecurity-nginx

COPY nginx.conf /etc/nginx/nginx.conf
COPY modsecurity.conf /etc/nginx/modsecurity.conf
COPY owasp-crs /etc/nginx/owasp-crs
COPY bWAPP /var/www/html/bWAPP