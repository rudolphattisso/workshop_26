# Contexte de build : services/ (comme les autres services)
#   docker build -f services/dashboard/Dockerfile services/

# 1) Construction des fichiers statiques
FROM node:20-alpine AS build
WORKDIR /src
COPY dashboard/package.json dashboard/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY dashboard/ ./
RUN npm test && npm run build

# 2) Service : nginx sans root (uid 101), aucune dépendance Node dans l'image finale
FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY dashboard/nginx.conf /etc/nginx/conf.d/default.conf
COPY dashboard/security-headers.conf /etc/nginx/security-headers.conf
COPY --from=build /src/dist /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=3 CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
