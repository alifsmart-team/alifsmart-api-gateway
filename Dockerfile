FROM node:18-alpine

WORKDIR /usr/src/app

# Install app dependencies
# A wildcard is used to ensure both package.json AND package-lock.json are copied
COPY package*.json ./

RUN npm install --omit=dev
# Kalo ada build step khusus (misal TypeScript), tambahin di sini
# RUN npm run build

# Bundle app source
COPY . .

# Expose port aplikasi
EXPOSE 3000

# Environment variables bisa di-set di sini atau lebih baik saat run (docker run -e atau di docker-compose)
# ENV NODE_ENV=production
# ENV PORT=3000
# ENV REDIS_HOST=... (dan seterusnya)

# Perintah untuk menjalankan aplikasi
CMD ["node", "server.js"]