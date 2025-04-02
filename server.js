const express = require('express');
const db = require('./config/db');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const path = require('path');
require('./queries/databaseQueries');
require('dotenv').config();
const { cloudinary, upload } = require('./config/cloudinary');
const multer = require('multer');
const { bucket } = require('./config/firebase');
const axios = require('axios');
const app = express();
app.use(cors({
    origin: ['http://localhost:3000', 'http://localhost:3001', 'https://barsikec.beget.tech', 'http://barsikec.beget.tech', 'https://startset-app.vercel.app'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'Origin', 'X-Requested-With'],
    exposedHeaders: ['Content-Range', 'X-Content-Range'],
    maxAge: 86400 // 24 часа
}));

// Добавляем middleware для обработки preflight запросов
app.options('*', cors());

// Добавляем middleware для всех запросов
app.use((req, res, next) => {
    console.log('Incoming request:', {
        method: req.method,
        path: req.path,
        headers: req.headers,
        body: req.body
    });

    const origin = req.headers.origin;
    if (origin && ['http://localhost:3000', 'http://localhost:3001', 'https://barsikec.beget.tech', 'http://barsikec.beget.tech', 'https://startset-app.vercel.app'].includes(origin)) {
        res.header('Access-Control-Allow-Origin', origin);
    }
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Accept, Origin, X-Requested-With');
    res.header('Access-Control-Max-Age', '86400');
    
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});

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

// Настройка multer для сохранения файлов
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, path.join(__dirname, 'uploads', 'avatars'));
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, req.user.id + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const localUpload = multer({
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB
    },
    fileFilter: function (req, file, cb) {
        // Проверяем тип файла
        if (!file.originalname.match(/\.(jpg|jpeg|png)$/)) {
            return cb(new Error('Только изображения разрешены!'), false);
        }
        cb(null, true);
    }
});

// Middleware для проверки JWT токена
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    console.log('Токен отсутствует в заголовке');
    return res.status(401).json({ message: 'Токен не найден' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) {
      console.log('Ошибка верификации токена:', err);
      return res.status(403).json({ message: 'Недействительный токен' });
    }
    req.user = user;
    next();
  });
};

app.post('/regpage', async (req, res) => {
    try {
        console.log('Получен запрос на регистрацию:', req.body);
        
        // Проверяем обязательные поля
        if (!req.body.username || !req.body.email || !req.body.password) {
            console.log('Отсутствуют обязательные поля:', {
                username: !!req.body.username,
                email: !!req.body.email,
                password: !!req.body.password
            });
            return res.status(400).json({
                success: false,
                error: 'Пожалуйста, заполните все обязательные поля'
            });
        }

        // Проверяем, существует ли пользователь
        console.log('Проверка существующего пользователя:', {
            username: req.body.username,
            email: req.body.email
        });
        
        const existingUser = await new Promise((resolve, reject) => {
            db.query('SELECT * FROM user WHERE username = ? OR email = ?', [req.body.username, req.body.email], (err, results) => {
                if (err) {
                    console.error("Ошибка при проверке пользователя:", err);
                    reject(err);
                } else {
                    resolve(results);
                }
            });
        });

        if (existingUser && existingUser.length > 0) {
            console.log('Пользователь уже существует:', existingUser[0]);
            return res.status(400).json({
                success: false,
                error: 'Пользователь с таким именем или email уже существует'
            });
        }

        // Хешируем пароль
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        console.log('Пароль успешно захеширован');

        // Проверяем наличие файла default.jpg
        const defaultAvatarPath = path.join(__dirname, 'uploads', 'avatars', 'default.jpg');
        console.log('Путь к дефолтному аватару:', defaultAvatarPath);
        
        // Создаем нового пользователя
        const insertUserQuery = 'INSERT INTO user (username, password, email, role, avatar, phone, address) VALUES (?, ?, ?, ?, ?, ?, ?)';
        const defaultAvatar = 'default.jpg'; // Используем только имя файла
        const insertValues = [
            req.body.username,
            hashedPassword,
            req.body.email,
            req.body.role || 'user',
            defaultAvatar,
            req.body.phone || null,
            req.body.address || null
        ];
        
        console.log('Подготовка к вставке пользователя:', {
            query: insertUserQuery,
            values: insertValues.map((v, i) => i === 1 ? '[HASHED]' : v)
        });

        const insertResult = await new Promise((resolve, reject) => {
            db.query(insertUserQuery, insertValues, (err, results) => {
                if (err) {
                    console.error("Ошибка при вставке пользователя:", err);
                    reject(err);
                } else {
                    resolve(results);
                }
            });
        });

        console.log('Результат вставки:', insertResult);

        if (!insertResult || !insertResult.insertId) {
            throw new Error('Не удалось получить ID созданного пользователя');
        }

        // Получаем данные созданного пользователя
        console.log('Получение данных созданного пользователя с ID:', insertResult.insertId);
        
        const newUser = await new Promise((resolve, reject) => {
            db.query('SELECT * FROM user WHERE id = ?', [insertResult.insertId], (err, results) => {
                if (err) {
                    console.error("Ошибка при получении данных пользователя:", err);
                    reject(err);
                } else if (!results || results.length === 0) {
                    reject(new Error('Пользователь не найден после создания'));
                } else {
                    console.log('Полученные данные пользователя:', results[0]);
                    resolve(results[0]);
                }
            });
        });

        console.log('Создан новый пользователь:', newUser);

        // Создаем токен
        const token = jwt.sign(
            { 
                id: newUser.id,
                username: newUser.username,
                role: newUser.role
            },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '24h' }
        );

        console.log('Токен успешно создан');

        // Отправляем ответ
        const response = {
            success: true,
            message: 'Регистрация успешна',
            user: {
                id: newUser.id,
                username: newUser.username,
                email: newUser.email,
                role: newUser.role,
                phone: newUser.phone,
                address: newUser.address,
                avatar: newUser.avatar || defaultAvatar
            },
            token
        };

        console.log('Отправка ответа:', response);
        res.json(response);
    } catch (error) {
        console.error('Ошибка при регистрации:', error);
        res.status(500).json({
            success: false,
            error: error.message || 'Ошибка при регистрации пользователя'
        });
    }
});

app.post('/logpage', async (req, res) => {
    try {
        const { username, password } = req.body;
        console.log('Получен запрос на авторизацию:', { username });

        // Поиск пользователя с использованием Promise
        const user = await new Promise((resolve, reject) => {
            db.query('SELECT * FROM user WHERE username = ?', [username], (err, results) => {
                if (err) {
                    console.error('Ошибка при поиске пользователя:', err);
                    reject(err);
                } else {
                    resolve(results);
                }
            });
        });

        console.log('Найден пользователь:', user[0]);

        if (!user || user.length === 0) {
            return res.status(401).json({ 
                success: false, 
                message: 'Пользователь не найден' 
            });
        }

        // Проверка пароля
        const validPassword = await bcrypt.compare(password, user[0].password);
        if (!validPassword) {
            return res.status(401).json({ 
                success: false, 
                message: 'Неверный пароль' 
            });
        }

        // Создание токена
        const token = jwt.sign(
            { 
                id: user[0].id, 
                username: user[0].username, 
                role: user[0].role 
            },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '24h' }
        );

        // Формирование ответа
        const response = {
            success: true,
            message: 'Вход выполнен успешно',
            token,
            user: {
                id: user[0].id,
                username: user[0].username,
                email: user[0].email,
                role: user[0].role,
                avatar: user[0].avatar || 'default.jpg',
                phone: user[0].phone,
                address: user[0].address
            }
        };

        console.log('Отправляем ответ:', response);
        res.json(response);
    } catch (error) {
        console.error('Ошибка при авторизации:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Ошибка сервера при авторизации' 
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
            res.setHeader('Access-Control-Allow-Origin', '*');
            res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
            res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
            res.json(results);
        });
    } catch (error) {
        console.error("Ошибка при обработке запроса /service:", error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/projects', async (req, res) => {
    try {
        console.log('Получен запрос на получение проектов');
        
        const projects = await new Promise((resolve, reject) => {
            db.query('SELECT * FROM projects ORDER BY id ASC', (err, results) => {
                if (err) {
                    console.error('Ошибка при получении проектов:', err);
                    reject(err);
                } else {
                    resolve(results);
                }
            });
        });

        console.log('Найдено проектов:', projects.length);
        
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
        res.json({
            success: true,
            data: projects
        });
    } catch (error) {
        console.error('Ошибка при получении проектов:', error);
        res.status(500).json({
            success: false,
            error: 'Ошибка при получении проектов'
        });
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
            res.setHeader('Access-Control-Allow-Origin', '*');
            res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
            res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
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
            res.setHeader('Access-Control-Allow-Origin', '*');
            res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
            res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
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
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
        res.json(executors);
    } catch (error) {
        console.error("Ошибка при получении исполнителей:", error);
        res.status(500).json({ error: 'Ошибка при получении исполнителей' });
    }
});

app.get('/orders', async (req, res) => {
    try {
        const userId = req.query.userId;
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
            res.setHeader('Access-Control-Allow-Origin', '*');
            res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
            res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
            res.json(results);
        });
    } catch (error) {
        console.error("Ошибка при обработке запроса /orders:", error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Эндпоинт для загрузки аватара
app.post('/upload-avatar', authenticateToken, localUpload.single('avatar'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({
                success: false,
                error: 'Файл не был загружен'
            });
        }

        // Получаем относительный путь к файлу
        const avatarPath = path.join('uploads', 'avatars', req.file.filename);

        // Обновляем аватар пользователя в базе данных
        const updateResult = await new Promise((resolve, reject) => {
            db.query(
                'UPDATE user SET avatar = ? WHERE id = ?',
                [req.file.filename, req.user.id],
                (err, results) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(results);
                    }
                }
            );
        });

        res.json({
            success: true,
            message: 'Аватар успешно обновлен',
            avatar: avatarPath
        });
    } catch (error) {
        console.error('Ошибка при загрузке аватара:', error);
        res.status(500).json({
            success: false,
            error: 'Ошибка при загрузке аватара'
        });
    }
});

// Эндпоинт для обновления профиля
app.put('/updateprofile', authenticateToken, async (req, res) => {
  try {
    console.log('Получен запрос на обновление профиля:', req.body);
    const userId = req.user.id;
    const { currentPassword, password, username, email, phone, address, avatar } = req.body;

    // Получаем текущего пользователя
    const [user] = await new Promise((resolve, reject) => {
      db.query('SELECT * FROM user WHERE id = ?', [userId], (error, results) => {
        if (error) {
          console.error('Ошибка при получении пользователя:', error);
          reject(error);
        }
        resolve(results);
      });
    });

    if (!user) {
      console.log('Пользователь не найден:', userId);
      return res.status(404).json({ message: 'Пользователь не найден' });
    }

    // Если есть текущий пароль, проверяем его
    if (currentPassword) {
      const validPassword = await bcrypt.compare(currentPassword, user.password);
      if (!validPassword) {
        console.log('Неверный текущий пароль для пользователя:', userId);
        return res.status(400).json({ message: 'Неверный текущий пароль' });
      }
    }

    // Формируем SQL запрос для обновления
    let updateQuery = 'UPDATE user SET ';
    const updateValues = [];

    if (username && username !== user.username) {
      // Проверяем уникальность username
      const [existingUser] = await new Promise((resolve, reject) => {
        db.query('SELECT id FROM user WHERE username = ? AND id != ?', [username, userId], (error, results) => {
          if (error) {
            console.error('Ошибка при проверке username:', error);
            reject(error);
          }
          resolve(results);
        });
      });

      if (existingUser) {
        console.log('Username уже занят:', username);
        return res.status(400).json({ message: 'Это имя пользователя уже занято' });
      }

      updateQuery += 'username = ?, ';
      updateValues.push(username);
    }

    if (email && email !== user.email) {
      // Проверяем уникальность email
      const [existingUser] = await new Promise((resolve, reject) => {
        db.query('SELECT id FROM user WHERE email = ? AND id != ?', [email, userId], (error, results) => {
          if (error) {
            console.error('Ошибка при проверке email:', error);
            reject(error);
          }
          resolve(results);
        });
      });

      if (existingUser) {
        console.log('Email уже используется:', email);
        return res.status(400).json({ message: 'Этот email уже используется' });
      }

      updateQuery += 'email = ?, ';
      updateValues.push(email);
    }

    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      updateQuery += 'password = ?, ';
      updateValues.push(hashedPassword);
    }

    if (phone) {
      updateQuery += 'phone = ?, ';
      updateValues.push(phone);
    }

    if (address) {
      updateQuery += 'address = ?, ';
      updateValues.push(address);
    }

    // Если есть URL аватара, добавляем его в запрос
    if (avatar) {
      updateQuery += 'avatar = ?, ';
      updateValues.push(avatar);
    }

    // Удаляем последнюю запятую и пробел
    updateQuery = updateQuery.slice(0, -2);

    // Добавляем условие WHERE
    updateQuery += ' WHERE id = ?';
    updateValues.push(userId);

    console.log('Выполняем обновление:', { query: updateQuery, values: updateValues });

    // Выполняем обновление
    await new Promise((resolve, reject) => {
      db.query(updateQuery, updateValues, (error) => {
        if (error) {
          console.error('Ошибка при обновлении профиля:', error);
          reject(error);
        }
        resolve();
      });
    });

    // Получаем обновленные данные пользователя
    const [updatedUser] = await new Promise((resolve, reject) => {
      db.query('SELECT * FROM user WHERE id = ?', [userId], (error, results) => {
        if (error) {
          console.error('Ошибка при получении обновленных данных:', error);
          reject(error);
        }
        resolve(results);
      });
    });

    // Создаем новый токен
    const newToken = jwt.sign(
      { 
        id: updatedUser.id,
        username: updatedUser.username,
        role: updatedUser.role
      },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    console.log('Профиль успешно обновлен для пользователя:', userId);
    res.json({ 
      success: true,
      message: 'Профиль успешно обновлен',
      user: {
        id: updatedUser.id,
        username: updatedUser.username,
        email: updatedUser.email,
        role: updatedUser.role,
        avatar: updatedUser.avatar || 'default.jpg',
        phone: updatedUser.phone,
        address: updatedUser.address
      },
      token: newToken
    });
  } catch (error) {
    console.error('Ошибка при обновлении профиля:', error);
    res.status(500).json({ message: 'Ошибка сервера при обновлении профиля' });
  }
});

// Добавляем обработку ошибок
app.use((err, req, res, next) => {
    console.error('Ошибка сервера:', err);
    res.status(500).json({
        success: false,
        message: 'Внутренняя ошибка сервера',
        error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Сервер запущен на порту ${PORT}`);
});
