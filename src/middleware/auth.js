import jwt from 'jsonwebtoken';
import redisClient from '../config/redis.js';
import { JWT_SECRET } from '../config/constants.js';

export const authenticate = async (req, res, next) => {
  try {
    // 1. Ambil token dari header
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) throw new Error('Token tidak ditemukan! 🔴');

    // 2. Cek cache Redis untuk token yang di-blacklist
    const isBlacklisted = await redisClient.get(`blacklist:${token}`);
    if (isBlacklisted) throw new Error('Token tidak valid!');

    // 3. Verifikasi JWT
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // 4. Attach user data ke request
    req.user = {
      id: decoded.userId,
      role: decoded.role,
      email: decoded.email
    };

    next();
  } catch (error) {
    res.status(401).json({ 
      success: false,
      error: 'Autentikasi gagal: ' + error.message 
    });
  }
};