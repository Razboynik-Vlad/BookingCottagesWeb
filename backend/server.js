const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const path = require('path');
const bcrypt = require('bcryptjs'); // Поменяли библиотеку
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET || 'gordeyut-secret-777';

// Проверка токена
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, message: 'Нужна авторизация' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ success: false, message: 'Сессия истекла' });
        req.user = user;
        next();
    });
};

// Маршруты страниц
app.get('/', (req, res) => res.sendFile(path.join(__dirname, '../frontend', 'index.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, '../frontend', 'dashboard.html')));

// API: Регистрация
app.post('/api/auth/register', async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.status(400).json({ success: false, message: 'Заполните все поля' });
    }

    try {
        const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userExists.rows.length > 0) {
            return res.status(400).json({ success: false, message: 'Этот email уже занят' });
        }

        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);

        // Используем lowercase имена колонок для надежности
        const newUser = await pool.query(
            'INSERT INTO users (name, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, name, email, role',
            [name, email, passwordHash, 'user']
        );

        res.status(201).json({ success: true, message: 'Регистрация прошла успешно!' });
    } catch (err) {
        console.error('Ошибка регистрации:', err); // Это покажет точную причину в консоли Render
        res.status(500).json({ success: false, message: 'Ошибка БД: убедитесь, что колонки созданы' });
    }
});

// API: Вход
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) return res.status(401).json({ success: false, message: 'Пользователь не найден' });

        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) return res.status(401).json({ success: false, message: 'Неверный пароль' });

        const token = jwt.sign({ id: user.id, name: user.name, role: user.role, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ success: true, token, user: { name: user.name, role: user.role, email: user.email } });
    } catch (err) {
        console.error('Ошибка входа:', err);
        res.status(500).json({ success: false, message: 'Ошибка сервера' });
    }
});

// === CRUD ЭНДПОИНТЫ (например, для коттеджей) ===

// Получить все коттеджи (Доступно всем)
app.get('/api/cottages', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM cottages');
        res.json({ success: true, data: result.rows });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Ошибка получения данных' });
    }
});

// Создать коттедж (Защищено: только авторизованные)
app.post('/api/cottages', authenticateToken, async (req, res) => {
    const { title, location } = req.body;
    const ownerId = req.user.id;

    try {
        const newCottage = await pool.query(
            'INSERT INTO cottages (title, location, "ownerId") VALUES ($1, $2, $3) RETURNING *',
            [title, location, ownerId]
        );
        res.status(201).json({ success: true, data: newCottage.rows[0] });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Ошибка создания' });
    }
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
    res.json({ success: true, user: req.user });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Сервер: http://localhost:${PORT}`));