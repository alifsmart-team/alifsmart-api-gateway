// routes/index.js
import { Router } from 'express';
import { createProxyMiddleware, fixRequestBody } from 'http-proxy-middleware';
import appConfig from '../config/index.js';
import authMiddleware from '../middleware/authMiddleware.js';
import cacheMiddleware from '../middleware/cacheMiddleware.js';
// import rateLimitMiddleware from '../middlewares/rateLimitMiddleware.js'; // bisa diterapkan global atau per route

const router = Router();

// Contoh konfigurasi routing
// Kita bisa iterasi dari appConfig.services
Object.values(appConfig.services).forEach(service => {
  const proxyOptions = {
    target: service.target,
    changeOrigin: true, // Penting buat virtual hosted sites
    // pathRewrite: { // Kalo mau rewrite path
    //   [`^${service.prefix}`]: '', // Hapus prefix sebelum dikirim ke service
    // },
    onProxyReq: fixRequestBody, // Untuk handle body POST/PUT/PATCH
    onError: (err, req, res) => {
      console.error(`Proxy error untuk ${service.prefix}:`, err);
      res.status(503).json({ message: `Servicenya lagi bobo kayaknya (${service.prefix}), coba lagi nanti ya.` });
    }
  };

  // Middleware spesifik per route atau global
  const routeMiddlewares = [];

  // Semua route di-protect kecuali route auth itu sendiri (login/register)
  // dan mungkin beberapa public route di content-service
  if (service.prefix !== appConfig.services.auth.prefix) {
      // Jika service BUKAN auth-service, pasang authMiddleware
      // Bisa juga lebih spesifik: misal hanya '/api/students/me' yg butuh auth
      routeMiddlewares.push(authMiddleware);
  }

  // Tambah cache untuk GET request (misalnya untuk content-service)
  if (service.prefix === appConfig.services.content.prefix) {
    routeMiddlewares.push(cacheMiddleware()); // default TTL
  }
  // Tambahkan middleware lain jika perlu, misal rate limiter per route

  router.use(service.prefix, ...routeMiddlewares, createProxyMiddleware(proxyOptions));
  console.log(`🚦 Proxying ${service.prefix} -> ${service.target}`);
});

export default router;