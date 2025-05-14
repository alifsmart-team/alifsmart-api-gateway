// app.js
import express from 'express';
import authRouter from './middleware/auth.js';  // Gunakan ekstensi .js

const app = express();
app.use('/auth', authRouter);

app.listen(3000, () => {
  console.log('Server running on port 3000');
});