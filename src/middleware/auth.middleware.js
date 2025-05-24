// middlewares/authMiddleware.js
import fetch from 'node-fetch'; // atau pake axios
import appConfig from '../config/index.js';

const authMiddleware = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Akses ditolak, token gak ada nih!' });
  }

  const token = authHeader.split(' ')[1];

  try {
    // Panggil auth-service buat validasi token
    // Pastikan AUTH_SERVICE_URL di .env atau config sudah benar
    // dan auth-service punya endpoint /validate-token
    const authServiceUrl = `${appConfig.services.auth.target}/validate-token`;

    const response = await fetch(authServiceUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}` // Teruskan token
      },
    });

    const data = await response.json();

    if (!response.ok || !data.valid) {
      return res.status(data.status || 401).json({ message: data.message || 'Token gak valid atau udah expired!' });
    }

    // Kalo valid, data user (misal: id, role) bisa ditempel ke request
    req.user = data.user;
    next();
  } catch (error) {
    console.error('Error pas validasi token ke auth-service:', error);
    return res.status(500).json({ message: 'Error internal pas ngecek token.' });
  }
};

export default authMiddleware;