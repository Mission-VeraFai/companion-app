# syntax = docker/dockerfile:1

# Adjust NODE_VERSION as desired
ARG NODE_VERSION=18.8.0
FROM node:${NODE_VERSION}-slim as base

LABEL fly_launch_runtime="Next.js"

# Next.js app lives here
WORKDIR /app

# Set production environment
ENV NODE_ENV=production


# Throw-away build stage to reduce size of final image
FROM base as build

# HITL approval gate: must be explicitly set to 'yes' to allow destructive rm -rf operations
# Usage: docker build --build-arg APPROVE_DELETE=yes ...
ARG APPROVE_DELETE=no

# Install packages needed to build node modules
RUN apt-get update -qq && \
    apt-get install --no-install-recommends python-is-python3 pkg-config build-essential && \
    find /var/lib/apt/lists/ -mindepth 1 -delete

# Install node modules
COPY --link package-lock.json package.json ./
RUN npm ci --ignore-scripts

# Copy application code
COPY --link . .

# Build application
RUN npm run build --if-present

# Remove development dependencies
RUN npm ci --omit=dev --ignore-scripts


# Final stage for app image
FROM base

# Copy built application
COPY --from=build /app /app

# Authentication enforcement: API_KEY must be set at runtime (e.g., via --env or secrets manager).
# REQUIRE_API_KEY=true instructs the application middleware to reject unauthenticated requests.
# Do NOT set a default value for API_KEY here; it must be injected at deploy time.
ENV REQUIRE_API_KEY=true
ENV API_KEY=""

# Write a startup script that aborts if API_KEY is not provided at runtime
RUN printf '#!/bin/sh\nset -e\nif [ -z "$API_KEY" ]; then\n  echo "ERROR: API_KEY environment variable is not set. The LLM endpoint requires authentication."\n  exit 1\nfi\nexec "$@"\n' > /app/docker-entrypoint.sh && chmod +x /app/docker-entrypoint.sh

# Require authentication before accessing the AI Agent.
# API_KEY must be supplied at runtime: docker run -e API_KEY=<your-secret> ...
# REQUIRE_AUTH=true signals the application to enforce authentication middleware.
ENV REQUIRE_AUTH=true
ARG API_KEY
RUN test -n "$API_KEY" || (echo "ERROR: API_KEY build-arg must be set to enable authentication" && exit 1)
ENV API_KEY=${API_KEY}

# Start the server by default, this can be overwritten at runtime
EXPOSE 3000
CMD [ "npm", "run", "start" ]
