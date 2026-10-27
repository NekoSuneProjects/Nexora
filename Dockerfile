FROM node:22-alpine
WORKDIR /app
COPY package*.json tsconfig.json ./
RUN npm install --omit=dev && npm install --no-save tsx typescript @types/node @types/pg
COPY apps ./apps
EXPOSE 3000
USER node
CMD ["npm", "start"]
