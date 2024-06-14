// auth/authController.js
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require('dotenv').config();

// Konfigurasi koneksi database MySQL
const db = require("../configs/database.js")


// Registrasi pengguna
const register = async (req, res) => {
    const { name, email, password } = req.body;

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user ke database
    db.query(
        'INSERT INTO Users (name, email, password) VALUES (?, ?, ?)',
        [name, email, hashedPassword],
        (err, results) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(400).json({ message: 'User already exists' });
                }
                return res.status(500).json({ message: 'Database error', error: err });
            }
            res.status(201).json({ message: 'User registered successfully' });
        }
    );
};

// login
const login = (req, res) => {
    const { email, password } = req.body;

    // Cari user di database
    db.query('SELECT * FROM Users WHERE email = ?', [email], async (err, results) => {
        if (err) return res.status(500).json({ message: 'Database error', error: err });
        if (results.length === 0) return res.status(400).json({ message: 'Invalid email or password' });

        const user = results[0];

        // Pastikan user.Password ada sebelum melanjutkan
        if (!user.password) return res.status(400).json({ message: 'Invalid email or password' });

        try {
            // Cek password
            const isPasswordValid = await bcrypt.compare(password, user.password);
            if (!isPasswordValid) return res.status(400).json({ message: 'Invalid email or password' });

            // Generate JWT
            const accessToken = jwt.sign({ id: user.id, email: user.email }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
            const refreshToken = jwt.sign({ id: user.id, email: user.email }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });

            // Simpan refresh token di database
            db.query('UPDATE Users SET refresh_token = ? WHERE Id = ?', [refreshToken, user.id], (err) => {
                if (err) return res.status(500).json({ message: 'Database error', error: err });
                res.json({ accessToken, refreshToken, names: user.name});
            });
        } catch (error) {
            console.error('Error during password comparison:', error);
            return res.status(500).json({ message: 'Internal server error' });
        }
    });
};

// Me-refresh token
const refreshToken = (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) return res.sendStatus(401);

    db.query('SELECT * FROM Users WHERE Refresh_Token = ?', [refreshToken], (err, results) => {
        if (err) return res.status(500).json({ message: 'Database error', error: err });
        if (results.length === 0) return res.sendStatus(403);

        const user = results[0];

        jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
            if (err) return res.sendStatus(403);

            const accessToken = jwt.sign({ id: user.id, email: user.email }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
            res.json({ accessToken });
        });
    });
};

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Fungsi logout
const logout = (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) return res.status(400).json({ message: 'Refresh token is required' });

    // Verifikasi refresh token
    db.query('SELECT * FROM Users WHERE Refresh_Token = ?', [refreshToken], (err, results) => {
        if (err) return res.status(500).json({ message: 'Database error', error: err });
        if (results.length === 0) return res.status(400).json({ message: 'Invalid refresh token' });

        // Hapus refresh token dari database
        db.query('UPDATE Users SET Refresh_Token = NULL WHERE Refresh_Token = ?', [refreshToken], (err, results) => {
            if (err) return res.status(500).json({ message: 'Database error', error: err });

            res.json({ message: 'Logged out successfully' });
        });
    });
};


module.exports = {
    register,
    login,
    logout,
    refreshToken,
    authenticateToken
};
