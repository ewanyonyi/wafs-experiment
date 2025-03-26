FROM nginx:alpine

RUN apk update && \
    apk add --no-cache nginx-mod-http-modsecurity

COPY nginx.conf /etc/nginx/nginx.conf
COPY modsecurity.conf /etc/nginx/modsecurity.conf
COPY owasp-crs /etc/nginx/owasp-crs
COPY bWAPP /var/www/html/bWAPP