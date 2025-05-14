// Konfigurasi Redis Client
import { createClient } from 'redis';
import 'dotenv/config';

// Pastikan variabel lingkungan sudah dimuat sebelum digunakan
const REDIS_USERNAME = process.env.REDIS_USERNAME;
const REDIS_PASSWORD = process.env.REDIS_PASSWORD;
const REDIS_HOST = process.env.REDIS_HOST;
const REDIS_PORT = process.env.REDIS_PORT; // Pastikan ini adalah angka jika perlu

// Validasi dasar variabel lingkungan
if (!REDIS_HOST || !REDIS_PORT) {
    console.error("FATAL ERROR: REDIS_HOST and REDIS_PORT must be defined in .env");
    process.exit(1); // Keluar dari aplikasi jika konfigurasi dasar tidak ada
}


const client = createClient({
    username: REDIS_USERNAME, // Bisa null/undefined jika tidak pakai username
    password: REDIS_PASSWORD, // Bisa null/undefined jika tidak pakai password
    socket: {
        host: REDIS_HOST,
        port: parseInt(REDIS_PORT, 10) // Pastikan port adalah integer
    }
});

// Event listener untuk error koneksi
client.on('error', err => console.error('Redis Client Error:', err));

// Event listener untuk sukses koneksi (opsional, tapi bagus untuk konfirmasi awal)
client.on('connect', () => console.log('Redis Client: Connecting...')); // Menunjukkan proses koneksi dimulai
client.on('ready', () => console.log('Redis Client: Successfully connected and ready!')); // Menunjukkan klien siap digunakan

// Menggunakan async/await untuk koneksi dan operasi
async function connectRedis() {
    try {
        await client.connect();
        // console.log('Redis Client: Connection established.'); // Bisa juga log di sini

        // Contoh operasi setelah koneksi berhasil
        await client.set('foo', 'bar');
        const result = await client.get('foo');
        console.log('Redis GET result for "foo":', result); // >>> bar

        // Jangan lupa tutup koneksi saat aplikasi akan mati (misal: saat SIGINT/SIGTERM)
        // process.on('SIGINT', async () => {
        //     console.log('Closing Redis connection...');
        //     await client.quit();
        //     process.exit(0);
        // });

    } catch (err) {
        console.error('Redis Client: Failed to connect or perform initial operation', err);
        // Opsi: Keluar dari aplikasi jika koneksi DB sangat krusial
        // process.exit(1);
    }
}

// Panggil fungsi koneksi
connectRedis();