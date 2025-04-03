const express = require('express');
const db = require('./config/db');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const path = require('path');
require('./queries/databaseQueries');

// Загружаем переменные окружения
require('dotenv').config();

// Проверяем наличие необходимых переменных окружения
console.log('Проверка переменных окружения:');
console.log('IMGBB_API_KEY:', process.env.IMGBB_API_KEY || 'Отсутствует');
console.log('JWT_SECRET:', process.env.JWT_SECRET ? 'Присутствует' : 'Отсутствует');
console.log('DB_HOST:', process.env.DB_HOST ? 'Присутствует' : 'Отсутствует');

// Устанавливаем значение IMGBB_API_KEY напрямую, если оно отсутствует в .env
if (!process.env.IMGBB_API_KEY) {
  process.env.IMGBB_API_KEY = '194fcc07333e5f7b8036a78bb24a89b0';
  console.log('IMGBB_API_KEY установлен напрямую');
}

const multer = require('multer');
const https = require('https');
const fs = require('fs');
const app = express();
app.use(cors({
    origin: ['http://localhost:3000', 'http://localhost:3001', 'https://barsikec.beget.tech', 'http://barsikec.beget.tech', 'https://startset-app.vercel.app', 'https://server-9va8.onrender.com'],
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
    if (origin && ['http://localhost:3000', 'http://localhost:3001', 'https://barsikec.beget.tech', 'http://barsikec.beget.tech', 'https://startset-app.vercel.app', 'https://server-9va8.onrender.com'].includes(origin)) {
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
            // Убедимся, что все URL изображений корректные
            const servicesWithUrls = results.map(service => ({
                ...service,
                background_image: service.background_image // URL уже с ImgBB
            }));
            
            res.setHeader('Access-Control-Allow-Origin', '*');
            res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
            res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
            res.json(servicesWithUrls);
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
app.post('/upload-avatar', authenticateToken, async (req, res) => {
  try {
    console.log('Получен запрос на загрузку аватара');
    
    if (!req.body.image) {
      console.log('Изображение не было загружено');
      return res.status(400).json({
        success: false,
        error: 'Изображение не было загружено'
      });
    }

    // Получаем base64 изображения
    const base64Image = req.body.image.split(',')[1];
    console.log('Base64 изображение получено');
    
    // Загружаем изображение на ImgBB
    const imgbbApiKey = process.env.IMGBB_API_KEY;
    console.log('ImgBB API Key:', imgbbApiKey ? 'Присутствует' : 'Отсутствует');
    
    if (!imgbbApiKey) {
      console.error('Отсутствует ключ ImgBB API');
      return res.status(500).json({
        success: false,
        error: 'Ошибка конфигурации сервера'
      });
    }
    
    const formData = new URLSearchParams();
    formData.append('key', imgbbApiKey);
    formData.append('image', base64Image);
    formData.append('name', `avatar-${req.user.id}-${Date.now()}`);
    
    console.log('Отправка запроса к ImgBB API');
    const imgbbResponse = await new Promise((resolve, reject) => {
      const options = {
        hostname: 'api.imgbb.com',
        path: '/1/upload',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': formData.toString().length
        }
      };
      
      const req = https.request(options, (res) => {
        let responseData = '';
        
        res.on('data', (chunk) => {
          responseData += chunk;
        });
        
        res.on('end', () => {
          try {
            console.log('Получен ответ от ImgBB API:', responseData);
            const parsedData = JSON.parse(responseData);
            resolve(parsedData);
          } catch (error) {
            console.error('Ошибка при парсинге ответа от ImgBB:', error);
            reject(error);
          }
        });
      });
      
      req.on('error', (error) => {
        console.error('Ошибка при запросе к ImgBB:', error);
        reject(error);
      });
      
      req.write(formData.toString());
      req.end();
    });
    
    console.log('Ответ от ImgBB:', imgbbResponse);
    
    if (!imgbbResponse.success) {
      console.error('Ошибка при загрузке на ImgBB:', imgbbResponse);
      return res.status(500).json({
        success: false,
        error: 'Ошибка при загрузке изображения на ImgBB'
      });
    }
    
    // Получаем URL загруженного изображения
    const imageUrl = imgbbResponse.data.url;
    console.log('URL загруженного изображения:', imageUrl);
    
    // Обновляем аватар пользователя в базе данных
    console.log('Обновление аватара в базе данных для пользователя:', req.user.id);
    const updateResult = await new Promise((resolve, reject) => {
      db.query(
        'UPDATE user SET avatar = ? WHERE id = ?',
        [imageUrl, req.user.id],
        (err, results) => {
          if (err) {
            console.error('Ошибка при обновлении аватара в БД:', err);
            reject(err);
          } else {
            console.log('Аватар успешно обновлен в БД');
            resolve(results);
          }
        }
      );
    });
    
    console.log('Отправка успешного ответа клиенту');
    res.json({
      success: true,
      message: 'Аватар успешно обновлен',
      avatar: imageUrl
    });
  } catch (error) {
    console.error('Ошибка при загрузке аватара:', error);
    res.status(500).json({
      success: false,
      error: 'Ошибка при загрузке аватара'
    });
  }
});

// Эндпоинт для обновления профиля пользователя
app.put('/updateprofile', authenticateToken, async (req, res) => {
  try {
    console.log('Получен запрос на обновление профиля:', req.body);
    const userId = req.user.id;
    const { username, email, phone, address } = req.body;

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

    // Проверяем уникальность username, если он изменился
    if (username && username !== user.username) {
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
    }

    // Проверяем уникальность email, если он изменился
    if (email && email !== user.email) {
      const [existingEmail] = await new Promise((resolve, reject) => {
        db.query('SELECT id FROM user WHERE email = ? AND id != ?', [email, userId], (error, results) => {
          if (error) {
            console.error('Ошибка при проверке email:', error);
            reject(error);
          }
          resolve(results);
        });
      });

      if (existingEmail) {
        console.log('Email уже занят:', email);
        return res.status(400).json({ message: 'Этот email уже используется' });
      }
    }

    // Обновляем данные пользователя
    const updateFields = [];
    const updateValues = [];

    if (username) {
      updateFields.push('username = ?');
      updateValues.push(username);
    }

    if (email) {
      updateFields.push('email = ?');
      updateValues.push(email);
    }

    if (phone !== undefined) {
      updateFields.push('phone = ?');
      updateValues.push(phone);
    }

    if (address !== undefined) {
      updateFields.push('address = ?');
      updateValues.push(address);
    }

    if (updateFields.length > 0) {
      updateValues.push(userId);
      const updateQuery = `UPDATE user SET ${updateFields.join(', ')} WHERE id = ?`;
      
      await new Promise((resolve, reject) => {
        db.query(updateQuery, updateValues, (error, results) => {
          if (error) {
            console.error('Ошибка при обновлении данных пользователя:', error);
            reject(error);
          }
          resolve(results);
        });
      });
    }

    // Получаем обновленного пользователя
    const [updatedUser] = await new Promise((resolve, reject) => {
      db.query('SELECT id, username, email, phone, address, avatar, role FROM user WHERE id = ?', [userId], (error, results) => {
        if (error) {
          console.error('Ошибка при получении обновленного пользователя:', error);
          reject(error);
        }
        resolve(results);
      });
    });

    console.log('Пользователь успешно обновлен:', updatedUser);

    // Генерируем новый токен
    const token = jwt.sign(
      { id: updatedUser.id, username: updatedUser.username, role: updatedUser.role },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    res.json({ user: updatedUser, token });
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

// Добавляем функцию для загрузки изображения услуги на ImgBB
const uploadServiceImageToImgBB = async (imageBase64) => {
    const imgbbApiKey = process.env.IMGBB_API_KEY;
    
    if (!imgbbApiKey) {
        throw new Error('ImgBB API key не настроен');
    }

    const formData = new URLSearchParams();
    formData.append('key', imgbbApiKey);
    formData.append('image', imageBase64);
    
    return new Promise((resolve, reject) => {
        const options = {
            hostname: 'api.imgbb.com',
            path: '/1/upload',
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': formData.toString().length
            }
        };

        const req = https.request(options, (res) => {
            let data = '';
            
            res.on('data', (chunk) => {
                data += chunk;
            });
            
            res.on('end', () => {
                try {
                    const response = JSON.parse(data);
                    if (response.success) {
                        resolve(response.data.url);
                    } else {
                        reject(new Error('Ошибка загрузки изображения'));
                    }
                } catch (error) {
                    reject(error);
                }
            });
        });

        req.on('error', reject);
        req.write(formData.toString());
        req.end();
    });
};

// Эндпоинт для добавления услуги
const upload = multer({ storage: multer.memoryStorage() });

app.post('/service', upload.single('background_image'), async (req, res) => {
    try {
        console.log('Получен запрос на добавление услуги');
        
        if (!req.file) {
            return res.status(400).json({ error: 'Изображение не было загружено' });
        }

        const imageFile = req.file;
        console.log('Получено изображение:', imageFile.originalname);

        // Загружаем изображение на ImgBB
        const imageUrl = await uploadServiceImageToImgBB(imageFile.buffer.toString('base64'));
        console.log('Изображение загружено на ImgBB:', imageUrl);

        const { title, description } = req.body;
        console.log('Данные услуги:', { title, description });

        const insertQuery = 'INSERT INTO services (title, description, background_image) VALUES (?, ?, ?)';
        db.query(insertQuery, [title, description, imageUrl], (err, result) => {
            if (err) {
                console.error('Ошибка при добавлении услуги:', err);
                return res.status(500).json({ error: 'Ошибка при добавлении услуги' });
            }
            
            const newService = {
                id: result.insertId,
                title,
                description,
                background_image: imageUrl
            };
            
            console.log('Услуга успешно добавлена:', newService);
            res.json(newService);
        });
    } catch (error) {
        console.error('Ошибка при обработке запроса:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Эндпоинт для обновления услуги
app.put('/service/:id', upload.single('background_image'), async (req, res) => {
    try {
        console.log('Получен запрос на обновление услуги');
        const { id } = req.params;
        
        let imageUrl = null;
        if (req.file) {
            const imageFile = req.file;
            console.log('Получено новое изображение:', imageFile.originalname);
            imageUrl = await uploadServiceImageToImgBB(imageFile.buffer.toString('base64'));
            console.log('Изображение загружено на ImgBB:', imageUrl);
        }

        const { title, description } = req.body;
        console.log('Данные для обновления:', { title, description, imageUrl });

        const updateQuery = 'UPDATE services SET title = ?, description = ?, background_image = COALESCE(?, background_image) WHERE id = ?';
        db.query(updateQuery, [title, description, imageUrl, id], (err, result) => {
            if (err) {
                console.error('Ошибка при обновлении услуги:', err);
                return res.status(500).json({ error: 'Ошибка при обновлении услуги' });
            }
            
            if (result.affectedRows === 0) {
                return res.status(404).json({ error: 'Услуга не найдена' });
            }
            
            const updatedService = {
                id: parseInt(id),
                title,
                description,
                background_image: imageUrl || req.body.background_image
            };
            
            console.log('Услуга успешно обновлена:', updatedService);
            res.json(updatedService);
        });
    } catch (error) {
        console.error('Ошибка при обработке запроса:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Эндпоинт для удаления услуги
app.delete('/service/:id', (req, res) => {
    const { id } = req.params;
    
    const deleteQuery = 'DELETE FROM services WHERE id = ?';
    db.query(deleteQuery, [id], (err, result) => {
        if (err) {
            console.error('Ошибка при удалении услуги:', err);
            return res.status(500).json({ error: 'Ошибка при удалении услуги' });
        }
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Услуга не найдена' });
        }
        
        res.json({ message: 'Услуга успешно удалена' });
    });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Сервер запущен на порту ${PORT}`);
});
