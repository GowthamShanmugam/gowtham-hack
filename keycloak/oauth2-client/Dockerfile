# Stage 1: build (ensure correct platform on Apple M1 / ARM)
FROM --platform=linux/amd64 node:18-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY public ./public
COPY src ./src
RUN npm run build

# Stage 2: serve (ensure linux/amd64)
FROM --platform=linux/amd64 nginx:stable-alpine

# Switch to root to allow directory setup
USER root
# Create and set permissions for nginx cache and run directories
RUN mkdir -p /var/cache/nginx/client_temp \
    /var/run && \
    chmod -R 777 /var/cache/nginx /var/run

# Provide a custom nginx configuration to listen on port 8080 instead of 80
RUN rm /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy built static files
COPY --from=build /app/build /usr/share/nginx/html

EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]