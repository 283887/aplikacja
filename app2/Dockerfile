FROM node:20-alpine

RUN apk add --no-cache openssl libc6-compat

WORKDIR /app

COPY package.json ./

RUN npm install

COPY . .

RUN npx prisma generate

EXPOSE 3000

# Komenda startowa
CMD ["sh", "-c", "npx prisma migrate deploy && npm start"]
