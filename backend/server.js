const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const path = require('path');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json());


// Указываем Express, где лежат ваши статические файлы (html, css, js)
// Если папка frontend находится уровнем выше, чем server.js:
// __dirname — это стандартная переменная Node.js, которая указывает на текущую папку
app.use(express.static(path.join(__dirname, '../frontend')));

// На любой запрос, который не является API, отдаем index.html
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend', 'index.html'));
});

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Эндпоинт для ВХОДА
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query(
            'SELECT role FROM users WHERE email = $1 AND password = $2',
            [email, password]
        );
        if (result.rows.length > 0) {
            res.json({ success: true, role: result.rows[0].role });
        } else {
            res.status(401).json({ success: false, message: 'Неверный email или пароль' });
        }
    } catch (err) {
        console.error('Ошибка БД:', err);
        res.status(500).json({ success: false, message: 'Ошибка сервера' });
    }
});

// Эндпоинт для РЕГИСТРАЦИИ
app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;
    try {
        // Проверяем, есть ли уже такой email
        const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userExists.rows.length > 0) {
            return res.status(400).json({ success: false, message: 'Пользователь с таким email уже существует' });
        }

        // Создаем нового пользователя с ролью 'user' по умолчанию
        // ВАЖНО: В реальном проекте пароль нужно хэшировать библиотекой bcrypt!
        await pool.query(
            'INSERT INTO users (email, password, role) VALUES ($1, $2, $3)',
            [email, password, 'user']
        );

        res.json({ success: true, message: 'Регистрация успешна!', role: 'user' });
    } catch (err) {
        console.error('Ошибка регистрации:', err);
        res.status(500).json({ success: false, message: 'Ошибка сервера при регистрации' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Сервер запущен на порту ${PORT}`));