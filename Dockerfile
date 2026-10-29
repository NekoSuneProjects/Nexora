FROM node:22-alpine
WORKDIR /app
COPY package*.json tsconfig.json ./
RUN npm install
COPY apps ./apps
COPY database ./database
COPY scripts/start-api.mjs ./scripts/start-api.mjs
EXPOSE 3000
USER node
CMD ["node", "scripts/start-api.mjs"]
