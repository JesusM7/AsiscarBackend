# Use Node.js LTS version as base image
FROM node:18-alpine

# Install OpenSSL 3 dependencies
RUN apk add --no-cache openssl3-dev

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

COPY . .

# Set environment variables
ENV NODE_ENV=production
ARG DATABASE_URL
ENV NODE_OPTIONS="--openssl-legacy-provider"

# Install dependencies with OpenSSL 3 support
RUN npm install --build-from-source --openssl-legacy-provider
# RUN npx prisma migrate dev --name init
# Expose port 3000
EXPOSE 3000

# Start the application
CMD ["sh", "-c", "npm run db:deploy && npm run dev"]