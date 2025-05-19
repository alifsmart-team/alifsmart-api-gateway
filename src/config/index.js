// config/index.js
import fs from 'fs';
import dotenv from 'dotenv'; // Masih berguna buat local dev atau env var non-secret

dotenv.config(); // Biar .env tetep kebaca buat variabel lain

// --- Helper buat baca secret dari file atau fallback ke env var ---
const getSecretValue = (fileEnvVar, directEnvVar, secretNameForLog) => {
  const filePath = process.env[fileEnvVar];
  if (filePath) {
    try {
      const secretValue = fs.readFileSync(filePath, 'utf8').trim();
      console.log(`🤫 Berhasil baca secret '${secretNameForLog}' dari file: ${filePath}`);
      return secretValue;
    } catch (err) {
      console.error(`❌ Gagal baca secret '${secretNameForLog}' dari file ${filePath}:`, err);
      // Di production, ini bisa jadi error fatal. Untuk dev, kita coba fallback.
    }
  }

  // Kalo gak ada file path atau gagal baca, coba fallback ke direct env var
  const directValue = process.env[directEnvVar];
  if (directValue) {
    console.warn(`↪️  Secret '${secretNameForLog}' gak kebaca dari file (atau file env var '${fileEnvVar}' gak diset). Pake fallback dari environment variable '${directEnvVar}'. (Ini oke buat dev, tapi di prod harusnya dari secret file!)`);
    return directValue;
  }

  console.error(`❌ Gagal total baca secret '${secretNameForLog}'. Gak ada file path di '${fileEnvVar}' dan gak ada fallback di '${directEnvVar}'.`);
  return undefined; // atau throw new Error(...) jika secret wajib ada di production
};

// --- Baca secret-secret penting ---
const redisPassword = getSecretValue('REDIS_PASSWORD_FILE', 'REDIS_PASSWORD', 'Redis Password');
const jwtSecret = getSecretValue('JWT_SECRET_FILE', 'JWT_SECRET', 'JWT Secret');

export default {
  port: process.env.PORT || 3000,
  nodeEnv: process.env.NODE_ENV || 'development',
  redis: {
    host: process.env.REDIS_HOST || 'localhost', // Default ke localhost kalo gak diset
    port: parseInt(process.env.REDIS_PORT, 10) || 6379, // Default port Redis
    tlsEnabled: process.env.REDIS_TLS_ENABLED === 'true', // Penting buat Redis Cloud
    password: redisPassword, // Hasil bacaan dari atas
  },
  jwtSecret: jwtSecret, // Hasil bacaan dari atas

  services: {
    auth: {
      target: process.env.AUTH_SERVICE_URL || 'http://alifsmart_auth_auth-service:3001', // Nama service di Swarm + port internalnya
      prefix: '/api/auth',
    },
    student: {
      target: process.env.STUDENT_SERVICE_URL || 'http://alifsmart_student_student-service:3002',
      prefix: '/api/students',
    },
    teacher: {
      target: process.env.TEACHER_SERVICE_URL || 'http://alifsmart_teacher_teacher-service:3003',
      prefix: '/api/teachers', // Diubah jadi plural, lebih umum
    },
    content: {
      target: process.env.CONTENT_SERVICE_URL || 'http://alifsmart_content_content-service:3004',
      prefix: '/api/content',
    },
    notification: {
      target: process.env.NOTIFICATION_SERVICE_URL || 'http://alifsmart_notification_notification-service:3005',
      prefix: '/api/notification',
    },
    attendance: {
      target: process.env.ATTENDANCE_SERVICE_URL || 'http://alifsmart_attendance_attendance-service:3006',
      prefix: '/api/attendance',
    },
    analytics: {
      target: process.env.ANALYTICS_SERVICE_URL || 'http://alifsmart_analytics_analytics-service:3007',
      prefix: '/api/analytics',
    },
    payment: {
      target: process.env.PAYMENT_SERVICE_URL || 'http://alifsmart_payment_payment-service:3008',
      prefix: '/api/payment',
    },
    // Kalo ada service baru, tinggal tambahin polanya di sini
  },
  cache: {
    defaultTTL: parseInt(process.env.CACHE_DEFAULT_TTL_SECONDS, 10) || 60, // detik
  },
  rateLimit: {
    windowMs: (parseInt(process.env.RATE_LIMIT_WINDOW_MINUTES, 10) || 15) * 60 * 1000, // 15 menit default
    max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS, 10) || 100, // 100 request default
    message: 'Lo kebanyakan request bro, IP lo kena limit sementara. Santai dulu ya!',
  },
};