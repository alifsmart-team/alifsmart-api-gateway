import 'dotenv/config'; // Muat variabel lingkungan pertama kali
import app from './app.js'; // Impor aplikasi Express yang sudah disiapkan

const PORT = process.env.PORT;

app.listen(PORT, () => {
  console.log(`API Gateway running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});