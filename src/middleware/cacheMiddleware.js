// middlewares/cacheMiddleware.js
import { redisClient, connectRedis } from '../services/redisClient.js';
import appConfig from '../config/index.js';

// await connectRedis(); // panggil di server.js sebelum middleware digunakan

const cacheMiddleware = (duration = appConfig.cache.defaultTTL) => {
  return async (req, res, next) => {
    // Hanya cache GET request
    if (req.method !== 'GET') {
      return next();
    }

    const key = `cache:${req.originalUrl || req.url}`;
    try {
      const cachedResponse = await redisClient.get(key);
      if (cachedResponse) {
        console.log(`CACHE HIT: ${key}`);
        return res.send(JSON.parse(cachedResponse));
      } else {
        console.log(`CACHE MISS: ${key}`);
        // Ganti res.send dengan versi yang di-override buat nyimpen ke cache
        const originalSend = res.send;
        res.send = (body) => {
          // Hanya cache response sukses (2xx)
          if (res.statusCode >= 200 && res.statusCode < 300) {
            redisClient.setex(key, duration, JSON.stringify(body));
          }
          return originalSend.call(res, body); // Balikin ke fungsi send asli
        };
        next();
      }
    } catch (err) {
      console.error('Cache error:', err);
      next(); // Kalo ada error di cache, lanjutin aja jangan sampe nge-block
    }
  };
};

export default cacheMiddleware;