const express = require('express');
const db = require('./config/db');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const path = require('path');
require('./queries/databaseQueries');
require('dotenv').config();
const app = express();
app.use(cors({
    origin: ['http://localhost:3000', 'http://localhost:3001', 'http://barsikec.beget.tech', 'https://barsikec.beget.tech'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(bodyParser.json());
// Serve static files from the React app
//app.use(express.static(path.join(__dirname, './client/build')));

// The "catchall" handler: for any request that doesn't
// match one above, send back React's index.html file.
//app.get('*', (req, res) => {
  //res.sendFile(path.join(__dirname, './client/build/index.html'));
//});
const { getActiveOrders, getCompletedOrders, getAllExecutors } = require('./queries/databaseQueries');


const avatarsPath = path.join(__dirname, 'uploads', 'avatars');
app.use('/uploads/avatars', express.static(avatarsPath));

const servicesBgPath = path.join(__dirname, 'uploads', 'services-bg');
app.use('/uploads/services-bg', express.static(servicesBgPath));
const projectsBgPath = path.join(__dirname, 'uploads', 'projects-bg');
app.use('/uploads/projects-bg', express.static(projectsBgPath));


app.post('/auth', async (req, res) => {
    try {
        const { username, password, email, role, phone, address, action } = req.body;
        console.log("Полученные данные:", req.body);

        // Проверяем наличие action
        if (!action) {
            return res.status(400).json({ error: 'Не указано действие (register/login)' });
        }

        // Если это регистрация
        if (action === 'register') {
            // Проверяем обязательные поля
            if (!username || !email || !password) {
                return res.status(400).json({ 
                    error: 'Все обязательные поля должны быть заполнены',
                    details: {
                        username: !username ? 'Имя пользователя обязательно' : null,
                        email: !email ? 'Email обязателен' : null,
                        password: !password ? 'Пароль обязателен' : null
                    }
                });
            }

            const defaultAvatarPath = 'default.jpg';

            // Проверяем существование пользователя
            const checkUserQuery = 'SELECT * FROM user WHERE username = ? OR email = ?';
            const existingUser = await new Promise((resolve, reject) => {
                db.query(checkUserQuery, [username, email], (err, results) => {
                    if (err) {
                        console.error("Ошибка при проверке пользователя:", err);
                        reject(err);
                    } else {
                        resolve(results);
                    }
                });
            });

            if (existingUser.length > 0) {
                const existingUsername = existingUser[0].username === username;
                return res.status(400).json({ 
                    error: existingUsername ? 
                        'Пользователь с таким именем уже существует' : 
                        'Пользователь с таким email уже существует' 
                });
            }

            // Хешируем пароль
            const hashedPassword = await bcrypt.hash(password, 10);

            // Создаем пользователя
            const insertUserQuery = 'INSERT INTO user (username, password, email, role, avatar, phone, address) VALUES (?, ?, ?, ?, ?, ?, ?)';
            const insertResult = await new Promise((resolve, reject) => {
                db.query(insertUserQuery, [
                    username, 
                    hashedPassword, 
                    email, 
                    role || 'user',
                    defaultAvatarPath,
                    phone || null,
                    address || null
                ], (err, results) => {
                    if (err) {
                        console.error("Ошибка при вставке пользователя:", err);
                        reject(err);
                    } else {
                        resolve(results);
                    }
                });
            });

            // Получаем ID нового пользователя
            const userId = insertResult.insertId;

            // Создаем токен
            const token = jwt.sign(
                { id: userId, username, role: role || 'user' },
                process.env.JWT_SECRET || 'your-secret-key',
                { expiresIn: '24h' }
            );

            return res.status(201).json({
                message: 'Пользователь успешно зарегистрирован',
                token,
                user: {
                    id: userId,
                    username,
                    email,
                    role: role || 'user',
                    avatar: defaultAvatarPath,
                    phone: phone || null,
                    address: address || null
                }
            });
        }
        // Если это авторизация
        else if (action === 'login') {
            if (!username || !password) {
                return res.status(400).json({ 
                    error: 'Пожалуйста, введите логин и пароль',
                    details: {
                        username: !username ? 'Имя пользователя обязательно' : null,
                        password: !password ? 'Пароль обязателен' : null
                    }
                });
            }

            const checkUserQuery = 'SELECT id, username, email, password, role, avatar, phone, address FROM user WHERE username = ?';
            console.log("Выполняется запрос:", checkUserQuery, "с параметром:", username);

            const results = await new Promise((resolve, reject) => {
                db.query(checkUserQuery, [username], (err, results) => {
                    if (err) {
                        console.error('Ошибка при выполнении запроса:', err);
                        reject(err);
                    } else {
                        console.log("Результаты запроса:", results);
                        resolve(results);
                    }
                });
            });

            if (results.length === 0) {
                console.log("Пользователь не найден:", username);
                return res.status(401).json({ error: 'Пользователь не найден' });
            }

            const user = results[0];
            console.log("Найден пользователь:", { 
                id: user.id, 
                username: user.username, 
                role: user.role,
                hasPassword: !!user.password 
            });

            const validPassword = await bcrypt.compare(password, user.password);
            console.log("Результат проверки пароля:", validPassword);

            if (!validPassword) {
                console.log("Неверный пароль для пользователя:", username);
                return res.status(401).json({ error: 'Неверный пароль' });
            }

            const token = jwt.sign(
                { id: user.id, username: user.username, role: user.role },
                process.env.JWT_SECRET || 'your-secret-key',
                { expiresIn: '24h' }
            );

            console.log("Успешная авторизация для пользователя:", username);
            res.json({
                token,
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    role: user.role,
                    avatar: user.avatar,
                    phone: user.phone,
                    address: user.address
                }
            });
        }
        // Если действие не указано
        else {
            return res.status(400).json({ error: 'Неверное действие. Используйте register или login' });
        }
    } catch (error) {
        console.error('Ошибка:', error);
        res.status(500).json({ 
            error: 'Внутренняя ошибка сервера', 
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

app.get('/service', async (req, res) => {
    try {
        const getServicesQuery = 'SELECT id, title, description, background_image, executor_id FROM services';
        db.query(getServicesQuery, (err, results) => {
            if (err) {
                console.error("Ошибка при получении данных услуг:", err);
                return res.status(500).json({ error: 'Ошибка при получении данных' });
            }
            res.setHeader('Content-Type', 'application/json');
            res.json(results);
        });
    } catch (error) {
        console.error("Ошибка при обработке запроса /service:", error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/projects', async (req, res) => {
    try {
        const getServicesQuery = 'SELECT id, projects_title, projects_description, projects_background FROM projects';
        db.query(getServicesQuery, (err, results) => {
            if (err) {
                console.error("Ошибка при получении данных проектов:", err);
                return res.status(500).json({ error: 'Ошибка при получении данных' });
            }
            res.setHeader('Content-Type', 'application/json');
            res.json(results);
        });
    } catch (error) {
        console.error("Ошибка при обработке запроса /projects:", error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/benefits', async (req, res) => {
    try {
        const getServicesQuery = 'SELECT id, benefit_title, benefit_description FROM benefits';
        db.query(getServicesQuery, (err, results) => {
            if (err) {
                console.error("Ошибка при получении данных преимуществ:", err);
                return res.status(500).json({ error: 'Ошибка при получении данных' });
            }
            res.setHeader('Content-Type', 'application/json');
            res.json(results);
        });
    } catch (error) {
        console.error("Ошибка при обработке запроса /benefits:", error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
app.get('/orderstatuses', async (req, res) => {
    try {
        const getStatusesQuery = 'SELECT * FROM order_statuses';
        db.query(getStatusesQuery, (err, results) => {
            if (err) {
                console.error("Ошибка при получении статусов:", err);
                return res.status(500).json({ error: 'Ошибка при получении данных' });
            }
            res.setHeader('Content-Type', 'application/json');
            res.json(results);
        });
    } catch (error) {
        console.error("Ошибка при обработке запроса /orderstatuses:", error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});


app.post('/createOrder', async (req, res) => {
    try {
        console.log('Запрос получен:', req.body);

        const { title_order, user_id, services_id, order_date, additionalInfo } = req.body;

        if (!title_order || !user_id || !services_id || !order_date || isNaN(parseInt(user_id)) || isNaN(parseInt(services_id))) {
            console.error('Валидация не пройдена. Некоторые поля пусты или некорректного типа.');
            return res.status(400).json({ message: 'Не все поля заполнены или некорректного типа' });
        }

        console.log('Данные перед запросом в БД:', { title_order, user_id, services_id, order_date, additionalInfo });

        const newOrder = await db.query(
            'INSERT INTO orders (title_order, user_id, services_id, order_date, executor_id, status_id, additional_info) VALUES (?, ?, ?, ?, 1, 1, ?)',
            [title_order, parseInt(user_id), parseInt(services_id), order_date, additionalInfo]
        );

        console.log('Результат запроса к БД:', newOrder);

        if (!newOrder || newOrder.affectedRows === 0) {
            console.error('Не удалось создать заказ');
            return res.status(500).json({ message: 'Не удалось создать заказ' });
        }

        console.log('Заказ успешно создан с ID:', newOrder.insertId);
        res.json({
            id: newOrder.insertId,
            title_order,
            user_id,
            services_id,
            order_date,
            additionalInfo
        });
    } catch (error) {
        console.error('Ошибка при создании заказа:', error);
        res.status(500).json({ message: 'Ошибка сервера' });
    }
});


app.get('/executors', async (req, res) => {
    try {
        console.log('Вызов getAllExecutors');
        const executors = await getAllExecutors();
        res.json(executors);
    } catch (error) {
        console.error("Ошибка при получении исполнителей:", error);
        res.status(500).json({ error: 'Ошибка при получении исполнителей' });
    }
});

app.get('/orders', async (req, res) => {
    try {
        const userId = req.query.userId; // Получаем userId из query параметров
        console.log("Получен запрос заказов для пользователя:", userId);

        const getOrdersQuery = `
            SELECT o.*, 
                   s.title as service_name,
                   e.fullname as executor_name,
                   os.status_name
            FROM orders o
            LEFT JOIN services s ON o.services_id = s.id
            LEFT JOIN executors e ON o.executor_id = e.id
            LEFT JOIN order_statuses os ON o.status_id = os.id
            WHERE o.user_id = ?
        `;
        
        db.query(getOrdersQuery, [userId], (err, results) => {
            if (err) {
                console.error("Ошибка при получении заказов:", err);
                return res.status(500).json({ error: 'Ошибка при получении данных' });
            }
            console.log("Полученные заказы для пользователя:", userId, results);
            res.setHeader('Content-Type', 'application/json');
            res.json(results);
        });
    } catch (error) {
        console.error("Ошибка при обработке запроса /orders:", error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});



const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Сервер запущен на порту ${PORT}`);
});
