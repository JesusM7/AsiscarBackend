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
ENV DATABASE_URL=${DATABASE_URL}
ENV NODE_OPTIONS="--openssl-legacy-provider"

# Install dependencies with OpenSSL 3 support
RUN npm install --build-from-source --openssl-legacy-provider

# Generate Prisma client
RUN npx prisma generate

# Run migrations
RUN npx prisma migrate dev

# Expose port 3000
EXPOSE 3000

# Start the application
CMD ["node", "index.js"]
