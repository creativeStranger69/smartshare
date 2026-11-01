# SmartShare production image
FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app

# Install only runtime dependencies first (better layer caching).
# If you commit a package-lock.json, change this to:  RUN npm ci --omit=dev
COPY package*.json ./
RUN npm install --omit=dev && npm cache clean --force

COPY . .

# Run as the unprivileged "node" user, never as root. Uploads live in a volume.
RUN mkdir -p /app/uploads && chown -R node:node /app
USER node
VOLUME ["/app/uploads"]
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server.js"]
