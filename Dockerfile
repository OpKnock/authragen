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
FROM node:20-alpine AS production

# Security: non-root user
RUN addgroup -g 1000 -S authragen && \
    adduser -u 1000 -S authragen -G authragen

WORKDIR /app

# Copy built artifacts
COPY --from=builder --chown=authragen:authragen /app/node_modules ./node_modules
COPY --chown=authragen:authragen package*.json ./
COPY --chown=authragen:authragen src/ ./src/
COPY --chown=authragen:authragen sdk-js/ ./sdk-js/
COPY --chown=authragen:authragen sdk_python/ ./sdk_python/
COPY --chown=authragen:authragen adapters/ ./adapters/
COPY --chown=authragen:authragen examples/ ./examples/
COPY --chown=authragen:authragen test/ ./test/
COPY --chown=authragen:authragen .gitignore ./
COPY --chown=authragen:authragen README.md ./
COPY --chown=authragen:authragen LICENSE* ./

# Create data directory with correct permissions
RUN mkdir -p /app/data && chown -R authragen:authragen /app/data

USER authragen

EXPOSE 8787

ENV NODE_ENV=production \
    PORT=8787 \
    AUTHRA_DATA=/app/data

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD node -e "require('http').get('http://localhost:8787/v1/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"

ENTRYPOINT ["node", "src/server.js"]