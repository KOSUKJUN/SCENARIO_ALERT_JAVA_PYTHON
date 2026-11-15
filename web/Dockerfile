# 관리 화면 (Vue 3 + Vite): node 로 빌드하고 nginx 로 서빙한다 (/api 는 server 로 프록시).
FROM node:20-alpine AS build
WORKDIR /app
ARG NPM_REGISTRY=https://registry.npmjs.org/
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund --registry "$NPM_REGISTRY"
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
