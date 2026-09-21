# AuthraGen - Multi-stage Dockerfile for production
# Build stage
FROM node:22-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache python3 make g++

# Copy package files
COPY package*.json ./
COPY sdk-js/ ./sdk-js/
COPY sdk_python/ ./sdk_python/

# Install production dependencies only
RUN npm ci --omit=dev && npm cache clean --force

# Production stage
FROM node:22-alpine AS production

# Security: run as the image's built-in non-root `node` user (uid/gid 1000).
# (Creating a fresh uid/gid 1000 fails: node:alpine already ships a `node`
# user holding those IDs.)
WORKDIR /app

# Copy built artifacts
COPY --from=builder --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node package*.json ./
COPY --chown=node:node src/ ./src/
COPY --chown=node:node sdk-js/ ./sdk-js/
COPY --chown=node:node sdk_python/ ./sdk_python/
COPY --chown=node:node adapters/ ./adapters/
COPY --chown=node:node README.md ./
COPY --chown=node:node LICENSE* ./

# Create data directory with correct permissions
RUN mkdir -p /app/data && chown -R node:node /app/data

USER node

EXPOSE 8787

ENV NODE_ENV=production \
    PORT=8787 \
    AUTHRA_DATA=/app/data

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD node -e "require('http').get('http://localhost:8787/v1/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"

ENTRYPOINT ["node", "src/server.js"]