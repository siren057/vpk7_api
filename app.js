const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');


const app = express();
const port = process.env.PORT || 3000;

// Middleware для обработки JSON
app.use(bodyParser.json());

// Секретный ключ для токенов
const SECRET_KEY = '123';

// Временные хранилища данных
const users = []; // Хранилище пользователей
const notes = []; // Хранилище заметок

// Middleware для проверки токена
const authenticate = (req, res, next) => {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(401).json({ success: false, message: 'Access denied. No token provided.' });
    }

    try {
        const decoded = jwt.verify(token.split(' ')[1], SECRET_KEY);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ success: false, message: 'Invalid token.' });
    }
};

// Регистрация пользователя
app.post('/register', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email and password are required.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    users.push({ email, password: hashedPassword });
    res.json({ success: true, message: 'User registered successfully.' });
});

// Вход пользователя
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    const user = users.find(u => u.email === email);
    if (!user) {
        return res.status(400).json({ success: false, message: 'Invalid email or password.' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        return res.status(400).json({ success: false, message: 'Invalid email or password.' });
    }

    const token = jwt.sign({ email: user.email }, SECRET_KEY, { expiresIn: '1h' });

    res.json({ success: true, token });
});

// Получение всех заметок (авторизованный запрос)
app.get('/notes', authenticate, (req, res) => {
    const userNotes = notes.filter(note => note.email === req.user.email);
    res.json({ success: true, data: userNotes });
});

// Добавление заметки (авторизованный запрос)
app.post('/notes', authenticate, (req, res) => {
    const { title, content } = req.body;

    if (!title || !content) {
        return res.status(400).json({ success: false, message: 'Title and content are required.' });
    }

    notes.push({ email: req.user.email, title, content });
    res.json({ success: true, message: 'Note added successfully.' });
});

// Удаление заметки (авторизованный запрос)
app.delete('/notes/:title', authenticate, (req, res) => {
    const { title } = req.params;

    const index = notes.findIndex(note => note.email === req.user.email && note.title === title);
    if (index === -1) {
        return res.status(404).json({ success: false, message: 'Note not found.' });
    }

    notes.splice(index, 1);
    res.json({ success: true, message: 'Note deleted successfully.' });
});

// Запуск сервера
app.listen(port,'0.0.0.0', () => {
    console.log(`API is running on http://localhost:${port}`);
});
