// services/redisClient.js
import Redis from 'ioredis';
import dotenv from 'dotenv';

dotenv.config();

// ... (redisOptions dan new Redis(redisOptions) tetap sama) ...
const redisOptions = {
  host: process.env.REDIS_HOST,
  port: parseInt(process.env.REDIS_PORT, 10),
  password: process.env.REDIS_PASSWORD,
  lazyConnect: true,
  ...(process.env.REDIS_TLS_ENABLED === 'true' && {
    tls: {
      rejectUnauthorized: false
    }
  })
};

const redisClient = new Redis(redisOptions);

redisClient.on('connect', () => {
  console.log('🌬️  Terhubung ke Redis Cloud!');
});

redisClient.on('error', (err) => {
  console.error('❌ Gagal terhubung ke Redis (dari event error):', err.message);
});

// Fungsi connectRedis yang udah di-update
const connectRedis = async () => {
  const { status } = redisClient;
  // Cek kalo statusnya udah 'connecting', 'connect', atau 'ready', gak usah ngapa-ngapain lagi
  if (status === 'connecting' || status === 'connect' || status === 'ready') {
    // console.log(`Redis udah/sedang proses konek (status: ${status}). Skip manggil connect() manual.`);
    return;
  }

  // Kalo statusnya beda (misal 'wait', 'end', 'close'), baru kita coba konek manual
  try {
    // console.log(`🔌 Mencoba konek manual ke Redis (status saat ini: ${status})...`);
    await redisClient.connect();
    // Kalo sukses, event 'connect' di atas yang bakal ngasih tau
  } catch (err) {
    // Error ini biasanya kalo .connect() dipanggil pas statusnya gak tepat
    // Kita udah coba handle di atas, tapi ini buat jaga-jaga
    if (!err.message.includes('Redis is already connecting/connected')) {
         console.error('❌ Error pas manggil redisClient.connect() secara eksplisit:', err.message);
    }
    // Kalo errornya "already connecting/connected", biarin aja, karena emang itu yang mau kita hindari log-nya
  }
};

export { redisClient, connectRedis };