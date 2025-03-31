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
    origin: ['http://localhost:3000', 'http://localhost:3001'],
    methods: ['GET', 'POST'],
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


app.post('/logpage', async (req, res) => {
    try {
        const { username, password } = req.body;
        console.log("Полученные данные для входа:", req.body);

        const checkUserQuery = 'SELECT id, username, email, password, role, avatar FROM user WHERE username = ?';

        const results = await new Promise((resolve, reject) => {
            db.query(checkUserQuery, [username], (err, results) => {
                if (err) reject(err);
                else resolve(results);
            });
        });


        if (results.length === 0) {
            console.warn("Пользователь не найден:", username);
            return res.status(400).json({ error: 'Пользователь не найден' });
        }

        const user = results[0];

        if (!user.password) {
            console.error("Пароль пользователя не найден в базе данных!");
            return res.status(500).json({ error: 'Ошибка: пароль пользователя не найден!' });
        }

        const match = await bcrypt.compare(password, user.password);

        if (!match) {
            console.warn("Неверный пароль для пользователя:", username);
            return res.status(400).json({ error: 'Неверный пароль' });
        }

        const token = jwt.sign({ id: user.id, username: user.username, role: user.role, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
        console.log("Успешный вход для пользователя:", username);
        console.log("Данные пользователя:", { 
            id: user.id, 
            username: user.username, 
            email: user.email, 
            role: user.role 
        });
        return res.status(200).json({
            message: 'Успешный вход',
            token,
            role: user.role,
            avatar: user.avatar,
            id: user.id,
            email: user.email // email добавлен в ответ
        });
        
        
    } catch (error) {
        console.error("Ошибка во время обработки запроса:", error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера', details: error.message });
    }
});

app.post('/regpage', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        console.log("Полученные данные:", req.body);

        const defaultAvatarPath = 'default.jpg';
        const avatarPath = defaultAvatarPath;

        console.log("Используемый путь к аватарке:", avatarPath);

        const checkUserQuery = 'SELECT * FROM user WHERE username = ?';
        db.query(checkUserQuery, [username], async (err, results) => {
            if (err) {
                console.error("Ошибка при проверке пользователя:", err);
                return res.status(500).json({ error: 'Ошибка при проверке пользователя' });
            }
            if (results.length > 0) {
                return res.status(400).json({ error: 'Пользователь с таким именем уже существует' });
            }

            const hashedPassword = await bcrypt.hash(password, 10);
            const role = 0;
            const insertUserQuery = 'INSERT INTO user (username, password, email, role, avatar) VALUES (?, ?, ?, ?, ?)';

            console.log("Данные для вставки:", [username, hashedPassword, email, role, avatarPath]);

            db.query(insertUserQuery, [username, hashedPassword, email, role, avatarPath], (err, results) => {
                if (err) {
                    console.error("Ошибка при вставке пользователя:", err);
                    return res.status(500).json({ error: 'Ошибка при вставке пользователя' });
                }
                return res.status(201).json({ message: 'Пользователь успешно зарегистрирован' });
            });
        });
    } catch (error) {
        console.error("Ошибка:", error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
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
                console.error("Ошибка при получении данных ghtbveotcnd:", err);
                return res.status(500).json({ error: 'Ошибка при получении данных' });
            }
            res.json(results);
        });
    } catch (error) {
        console.error("Ошибка при обработке запроса /benefits:", error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
app.get('/orderstatuses', async (req, res) => {
    try {
        const getServicesQuery = 'SELECT id, status_name FROM order_statuses';
        db.query(getServicesQuery, (err, results) => {
            if (err) {
                console.error("Ошибка при получении данных статусов заказаов:", err);
                return res.status(500).json({ error: 'Ошибка при получении данных' });
            }
            res.json(results);
        });
    } catch (error) {
        console.error("Ошибка при обработке запроса /orderstatuses", error);
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
        const activeOrders = await getActiveOrders();
        const completedOrders = await getCompletedOrders();
        
        res.json({ activeOrders, completedOrders });
    } catch (error) {
        console.error("Ошибка при получении заказов:", error);
        res.status(500).json({ error: 'Ошибка при получении заказов' });
    }
});



const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Сервер запущен на порту ${PORT}`);
});
