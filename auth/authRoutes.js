// auth/authRoutes.js
const express = require('express');
const { register, login, refreshToken, authenticateToken, logout } = require('./authController');

const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.post('/logout', logout);
router.post('/token', refreshToken);
router.get('/protected', authenticateToken, (req, res) => {
    res.json({ message: 'This is a protected route', user: req.user });
});

module.exports = router;