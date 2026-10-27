FROM node:22-alpine
WORKDIR /app
COPY package*.json tsconfig.json ./
RUN npm install
COPY apps ./apps
EXPOSE 3000
USER node
CMD ["npm", "start"]
