// server.js
import express from 'express';
import morgan from 'morgan';
import helmet from 'helmet';
import cors from 'cors';
import dotenv from 'dotenv';

import appConfig from './src/config/index.js';
import { connectRedis, redisClient } from './src/services/redisClient.js'; // Import redisClient juga
import apiRoutes from './src/routes/index.js';
import rateLimitMiddleware from './src/middleware/rateLimitMiddleware.js'; // Rate limiter global

dotenv.config(); // Panggil di awal

const app = express();
const PORT = appConfig.port;

// Fungsi untuk start server
async function startServer() {
  // Coba konek ke Redis dulu
  try {
    if (redisClient.status !== 'ready' && redisClient.status !== 'connect') {
        await connectRedis(); // panggil fungsi connectRedis
    }
    if (redisClient.status !== 'ready' && redisClient.status !== 'connecting') {
        console.warn("Redis belum siap, tapi server tetep jalan. Rate limiting & caching mungkin gak fungsi.")
    }
  } catch (err) {
    console.error("Gagal konek Redis pas startup server:", err);
    // Bisa pilih untuk exit proses jika Redis kritikal
    // process.exit(1);
  }


  // Middlewares Global
  app.use(helmet()); // Amankan HTTP headers
  app.use(cors({ // Atur CORS sesuai kebutuhan
    // origin: 'http://your-frontend-domain.com'
  }));
  app.use(morgan(process.env.NODE_ENV === 'development' ? 'dev' : 'combined')); // Logger
  app.use(express.json()); // Parser JSON body
  app.use(express.urlencoded({ extended: true })); // Parser URL-encoded body

  // Pasang Rate Limiter Global (bisa juga per route kalo mau)
  app.use(rateLimitMiddleware);

  // Welcome Route
  app.get('/', (req, res) => {
    res.json({ message: '👋 Halo dari AlifSmart API Gateway! Siap melayani!' });
  });

  // Pasang Proxy Routes
  app.use(apiRoutes);

  // Error Handling Middleware (taruh paling bawah)
  app.use((err, req, res, next) => {
    console.error("💥 Ada error nih:", err.stack);
    res.status(err.status || 500).json({
      message: err.message || 'Waduh, ada yang error di server gateway nih!',
      // error: process.env.NODE_ENV === 'development' ? err : {} // Tampilkan detail error di dev
    });
  });

  app.listen(PORT, () => {
    console.log(`🚀 API Gateway AlifSmart udah ngacir di http://localhost:${PORT}`);
    console.log(`NODE_ENV: ${process.env.NODE_ENV}`);
  });
}

startServer().catch(err => {
    console.error("💥 Gagal total ngejalanin server:", err);
    process.exit(1);
});