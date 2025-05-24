// middlewares/rateLimitMiddleware.js
import rateLimit from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import { redisClient, connectRedis } from '../services/cache.service.js';
import appConfig from '../config/index.js';

// Pastikan redis terkoneksi sebelum store dibuat
// await connectRedis(); // panggil di server.js sebelum middleware digunakan

const limiter = rateLimit({
  store: new RedisStore({
    sendCommand: (...args) => redisClient.call(...args), // ioredis butuh call
  }),
  windowMs: appConfig.rateLimit.windowMs,
  max: appConfig.rateLimit.max,
  message: appConfig.rateLimit.message,
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  keyGenerator: (req) => {
    // Bisa juga pake user ID kalo udah login: req.user.id || req.ip
    return req.ip;
  }
});

export default limiter;