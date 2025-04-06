const express = require('express');
const db = require('./config/db');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const path = require('path');
const multer = require('multer');
const https = require('https');
const fs = require('fs');

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

// Настройка multer для обработки файлов
const storage = multer.memoryStorage();
const fileFilter = (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
        cb(null, true);
    } else {
        cb(new Error('Неверный тип файла. Разрешены только изображения.'), false);
    }
};

const upload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: {
        fileSize: 32 * 1024 * 1024 // 32MB
    }
});

const corsOptions = {
    origin: ['http://localhost:3000', 'http://localhost:3001', 'https://barsikec.beget.tech', 'http://barsikec.beget.tech', 'https://startset-app.vercel.app', 'https://server-9va8.onrender.com'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'Origin', 'X-Requested-With'],
    exposedHeaders: ['Content-Range', 'X-Content-Range'],
    credentials: true,
    maxAge: 86400 // 24 часа
};

const app = express();

app.use(cors(corsOptions));

// Обработка preflight запросов
app.options('*', cors(corsOptions));

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
        res.header('Access-Control-Allow-Credentials', 'true');
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
        const getServicesQuery = 'SELECT id, title, description, background_image, executor_id, is_dark_theme FROM services';
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
        console.log('Получен запрос на получение проектов');
        
        const projects = await new Promise((resolve, reject) => {
            db.query('SELECT id, projects_title, projects_description, projects_background, is_dark_theme FROM projects ORDER BY id ASC', (err, results) => {
            if (err) {
                    console.error('Ошибка при получении проектов:', err);
                    reject(err);
                } else {
                    // Преобразуем is_dark_theme из числа (0/1) в boolean
                    const formattedResults = results.map(project => ({
                        ...project,
                        is_dark_theme: Boolean(project.is_dark_theme)
                    }));
                    resolve(formattedResults);
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

// Создание нового преимущества
app.post('/benefits', async (req, res) => {
    try {
        console.log('Получен запрос на создание преимущества:', req.body);
        const { benefit_title, benefit_description } = req.body;

        // Проверяем наличие обязательных полей
        if (!benefit_title?.trim() || !benefit_description?.trim()) {
            console.error('Отсутствуют обязательные поля:', { benefit_title, benefit_description });
            return res.status(400).json({
                success: false,
                error: 'Пожалуйста, заполните все обязательные поля (название и описание)'
            });
        }

        // Создаем новое преимущество в базе данных
        const insertQuery = 'INSERT INTO benefits (benefit_title, benefit_description) VALUES (?, ?)';
        
        db.query(insertQuery, [benefit_title.trim(), benefit_description.trim()], (err, result) => {
            if (err) {
                console.error("Ошибка при создании преимущества в БД:", err);
                return res.status(500).json({
                    success: false,
                    error: 'Ошибка при создании преимущества в базе данных'
                });
            }
            
            console.log('Преимущество успешно создано:', result);
            res.json({
                success: true,
                message: 'Преимущество успешно создано',
                data: {
                    id: result.insertId,
                    benefit_title: benefit_title.trim(),
                    benefit_description: benefit_description.trim()
                }
            });
        });
    } catch (error) {
        console.error("Ошибка при создании преимущества:", error);
        res.status(500).json({
            success: false,
            error: 'Ошибка сервера'
        });
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

        const { 
            project_name, 
            user_id, 
            service_id, 
            template_id,
            site_type,
            blocks_count,
            price,
            additional_info,
            need_receipt,
            status_id,
            executor_id,
            order_date
        } = req.body;

        // Проверяем обязательные поля
        if (!project_name || !user_id || !service_id || !executor_id || !status_id || !order_date) {
            console.error('Валидация не пройдена. Некоторые поля пусты или некорректного типа.');
            return res.status(400).json({ message: 'Не все обязательные поля заполнены' });
        }

        const insertQuery = `
            INSERT INTO orders (
                project_name, user_id, service_id, template_id, 
                site_type, blocks_count, price, additional_info,
                need_receipt, status_id, executor_id, order_date
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;

        const values = [
            project_name, user_id, service_id, template_id,
            site_type, blocks_count, price, additional_info,
            need_receipt ? 1 : 0, status_id, executor_id, order_date
        ];

        db.query(insertQuery, values, (err, result) => {
            if (err) {
                console.error('Ошибка при создании заказа:', err);
                return res.status(500).json({ message: 'Ошибка при создании заказа' });
            }

            res.json({
                success: true,
                orderId: result.insertId,
                message: 'Заказ успешно создан'
            });
        });
    } catch (error) {
        console.error('Ошибка при создании заказа:', error);
        res.status(500).json({ message: 'Ошибка сервера при создании заказа' });
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
            LEFT JOIN services s ON o.service_id = s.id
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

// Загрузка изображения для услуги
app.post('/services/:id/upload-image', upload.single('image'), async (req, res) => {
    try {
        console.log('Получен запрос на загрузку изображения:', {
            file: req.file,
            body: req.body,
            params: req.params
        });

        if (!req.file) {
            return res.status(400).json({ error: 'Изображение не было загружено' });
        }

        // Конвертируем буфер в base64
        const base64Image = req.file.buffer.toString('base64');

        // Загружаем изображение на ImgBB
        const postData = new URLSearchParams();
        postData.append('image', base64Image);
        postData.append('key', process.env.IMGBB_API_KEY);

        const options = {
            hostname: 'api.imgbb.com',
            path: '/1/upload',
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': postData.toString().length
            }
        };

        const imgbbResponse = await new Promise((resolve, reject) => {
            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', (chunk) => {
                    data += chunk;
                });
                res.on('end', () => {
                    try {
                        resolve(JSON.parse(data));
                    } catch (e) {
                        reject(e);
                    }
                });
            });

            req.on('error', (error) => {
                reject(error);
            });

            req.write(postData.toString());
            req.end();
        });

        if (!imgbbResponse.success) {
            throw new Error('Ошибка при загрузке изображения на ImgBB');
        }

        const imageUrl = imgbbResponse.data.url;

        // Обновляем URL изображения в базе данных
        const updateQuery = 'UPDATE services SET background_image = ? WHERE id = ?';
        db.query(updateQuery, [imageUrl, req.params.id], (err, result) => {
            if (err) {
                console.error("Ошибка при обновлении изображения услуги:", err);
                return res.status(500).json({ error: 'Ошибка при обновлении изображения услуги' });
            }
            res.json({ 
                success: true, 
                imageUrl,
                message: 'Изображение успешно загружено и обновлено'
            });
        });
    } catch (error) {
        console.error("Ошибка при обработке запроса загрузки изображения:", error);
        res.status(500).json({ error: 'Ошибка сервера при загрузке изображения' });
    }
});

// Обновление услуги
app.put('/services/:id', upload.single('image'), async (req, res) => {
    try {
        const { id } = req.params;
        const { title, description, is_dark_theme } = req.body;
        let imageUrl = null;

        // Если загружено новое изображение
        if (req.file) {
            // Конвертируем буфер в base64
            const base64Image = req.file.buffer.toString('base64');

            // Загружаем изображение на ImgBB
            const postData = new URLSearchParams();
            postData.append('image', base64Image);
            postData.append('key', process.env.IMGBB_API_KEY);

            const options = {
                hostname: 'api.imgbb.com',
                path: '/1/upload',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Content-Length': postData.toString().length
                }
            };

            const imgbbResponse = await new Promise((resolve, reject) => {
                const req = https.request(options, (res) => {
                    let data = '';
                    res.on('data', (chunk) => {
                        data += chunk;
                    });
                    res.on('end', () => {
                        try {
                            resolve(JSON.parse(data));
                        } catch (e) {
                            reject(e);
                        }
                    });
                });

                req.on('error', (error) => {
                    reject(error);
                });

                req.write(postData.toString());
                req.end();
            });

            if (!imgbbResponse.success) {
                throw new Error('Ошибка при загрузке изображения на ImgBB');
            }

            imageUrl = imgbbResponse.data.url;
        }

        // Формируем SQL запрос
        const updateFields = [];
        const updateValues = [];
        
        if (title) {
            updateFields.push('title = ?');
            updateValues.push(title);
        }
        
        if (description) {
            updateFields.push('description = ?');
            updateValues.push(description);
        }
        
        if (imageUrl) {
            updateFields.push('background_image = ?');
            updateValues.push(imageUrl);
        }

        if (is_dark_theme !== undefined) {
            updateFields.push('is_dark_theme = ?');
            updateValues.push(is_dark_theme === 'true' ? 1 : 0);
        }

        // Если нет полей для обновления, возвращаем ошибку
        if (updateFields.length === 0) {
            return res.status(400).json({ error: 'Нет данных для обновления' });
        }

        // Добавляем id в конец массива значений
        updateValues.push(id);

        // Формируем финальный SQL запрос
        const updateQuery = `UPDATE services SET ${updateFields.join(', ')} WHERE id = ?`;

        console.log('SQL Query:', updateQuery);
        console.log('Values:', updateValues);

        // Выполняем обновление
        db.query(updateQuery, updateValues, (err, result) => {
            if (err) {
                console.error("Ошибка при обновлении услуги:", err);
                return res.status(500).json({ error: 'Ошибка при обновлении услуги' });
            }
            res.json({ 
                success: true,
                message: 'Услуга успешно обновлена',
                data: { id, title, description, background_image: imageUrl }
            });
        });
    } catch (error) {
        console.error("Ошибка при обработке запроса /services/:id:", error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Создание новой услуги
app.post('/services', upload.single('image'), async (req, res) => {
    try {
        console.log('Получен запрос на создание услуги:', {
            body: req.body,
            file: req.file ? {
                fieldname: req.file.fieldname,
                originalname: req.file.originalname,
                mimetype: req.file.mimetype,
                size: req.file.size,
                buffer: req.file.buffer ? 'Buffer present' : 'No buffer'
            } : 'No file'
        });

        const { title, description, is_dark_theme } = req.body;
        let imageUrl = null;

        // Проверяем наличие обязательных полей
        if (!title || !description) {
            console.error('Отсутствуют обязательные поля:', { title, description });
            return res.status(400).json({ 
                success: false,
                error: 'Пожалуйста, заполните все обязательные поля (название и описание)'
            });
        }

        // Если загружено изображение
        if (req.file && req.file.buffer) {
            try {
                console.log('Начинаем загрузку изображения на ImgBB');
                // Конвертируем буфер в base64
                const base64Image = req.file.buffer.toString('base64');
                console.log('Изображение конвертировано в base64');

                // Загружаем изображение на ImgBB
                const postData = new URLSearchParams();
                postData.append('image', base64Image);
                postData.append('key', process.env.IMGBB_API_KEY);

                const options = {
                    hostname: 'api.imgbb.com',
                    path: '/1/upload',
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }
                };

                console.log('Отправляем запрос к ImgBB API');
                const imgbbResponse = await new Promise((resolve, reject) => {
                    const req = https.request(options, (res) => {
                        let data = '';
                        res.on('data', (chunk) => {
                            data += chunk;
                        });
                        res.on('end', () => {
                            try {
                                const parsedData = JSON.parse(data);
                                console.log('Получен ответ от ImgBB:', parsedData);
                                resolve(parsedData);
                            } catch (e) {
                                console.error('Ошибка парсинга ответа ImgBB:', e);
                                reject(e);
                            }
                        });
                    });

                    req.on('error', (error) => {
                        console.error('Ошибка запроса к ImgBB:', error);
                        reject(error);
                    });

                    req.write(postData.toString());
                    req.end();
                });

                if (!imgbbResponse.success) {
                    console.error('Ошибка от ImgBB:', imgbbResponse);
                    throw new Error('Ошибка при загрузке изображения на ImgBB');
                }

                imageUrl = imgbbResponse.data.url;
                console.log('Изображение успешно загружено:', imageUrl);
            } catch (imgError) {
                console.error('Ошибка при обработке изображения:', imgError);
                return res.status(500).json({ 
                    success: false,
                    error: 'Ошибка при загрузке изображения. Пожалуйста, попробуйте другое изображение или повторите попытку позже.'
                });
            }
        } else {
            console.log('Изображение не было предоставлено');
        }

        // Создаем новую услугу в базе данных
        console.log('Создаем запись в БД:', { title, description, imageUrl, is_dark_theme });
        const defaultExecutorId = 1; // ID исполнителя по умолчанию
        const insertQuery = 'INSERT INTO services (title, description, background_image, executor_id, is_dark_theme) VALUES (?, ?, ?, ?, ?)';
        
        db.query(insertQuery, [
            title, 
            description, 
            imageUrl, 
            defaultExecutorId, 
            is_dark_theme === 'true' ? 1 : 0
        ], (err, result) => {
            if (err) {
                console.error("Ошибка при создании услуги в БД:", err);
                return res.status(500).json({ 
                    success: false,
                    error: 'Ошибка при создании услуги в базе данных'
                });
            }
            
            console.log('Услуга успешно создана:', result);
            res.json({ 
                success: true,
                message: 'Услуга успешно создана',
                data: { 
                    id: result.insertId,
                    title,
                    description,
                    background_image: imageUrl,
                    executor_id: defaultExecutorId,
                    is_dark_theme: is_dark_theme === 'true'
                }
            });
        });
    } catch (error) {
        console.error("Ошибка при обработке запроса /services:", error);
        res.status(500).json({ 
            success: false,
            error: 'Внутренняя ошибка сервера. Пожалуйста, попробуйте позже.'
        });
    }
});

// Удаление услуги
app.delete('/services/:id', async (req, res) => {
    try {
        const { id } = req.params;

        console.log('Получен запрос на удаление услуги:', { id });

        // Проверяем существование услуги
        const checkQuery = 'SELECT * FROM services WHERE id = ?';
        const service = await new Promise((resolve, reject) => {
            db.query(checkQuery, [id], (err, results) => {
                if (err) {
                    console.error('Ошибка при проверке услуги:', err);
                    reject(err);
                } else {
                    resolve(results[0]);
                }
            });
        });

        if (!service) {
            console.log('Услуга не найдена:', { id });
            return res.status(404).json({
                success: false,
                error: 'Услуга не найдена'
            });
        }

        // Удаляем услугу
        const deleteQuery = 'DELETE FROM services WHERE id = ?';
        await new Promise((resolve, reject) => {
            db.query(deleteQuery, [id], (err, result) => {
                if (err) {
                    console.error('Ошибка при удалении услуги:', err);
                    reject(err);
                } else {
                    resolve(result);
                }
            });
        });

        console.log('Услуга успешно удалена:', { id });
        res.json({
            success: true,
            message: 'Услуга успешно удалена'
        });
    } catch (error) {
        console.error('Ошибка при обработке запроса на удаление:', error);
        res.status(500).json({
            success: false,
            error: 'Ошибка при удалении услуги'
        });
    }
});

// Эндпоинт для создания проекта
app.post('/projects', upload.single('projects_background'), async (req, res) => {
    try {
        console.log('Получен запрос на создание проекта:', {
            body: req.body,
            file: req.file ? {
                fieldname: req.file.fieldname,
                originalname: req.file.originalname,
                mimetype: req.file.mimetype,
                size: req.file.size
            } : 'No file'
        });

        const { projects_title, projects_description, is_dark_theme } = req.body;
        console.log('Полученные данные:', { projects_title, projects_description, is_dark_theme });

        let imageUrl = null;

        // Если есть файл изображения
        if (req.file) {
            try {
                console.log('Начинаем обработку изображения');
                // Конвертируем буфер в base64
                const base64Image = req.file.buffer.toString('base64');
                console.log('Изображение конвертировано в base64, размер:', base64Image.length);

                // Загружаем изображение на ImgBB
                const postData = new URLSearchParams();
                postData.append('image', base64Image);
                postData.append('key', process.env.IMGBB_API_KEY);

                console.log('Отправляем запрос к ImgBB API');
                const options = {
                    hostname: 'api.imgbb.com',
                    path: '/1/upload',
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Content-Length': postData.toString().length
                    }
                };

                const imgbbResponse = await new Promise((resolve, reject) => {
                    const req = https.request(options, (res) => {
                        let data = '';
                        res.on('data', (chunk) => {
                            data += chunk;
                        });
                        res.on('end', () => {
                            try {
                                const parsedData = JSON.parse(data);
                                console.log('Получен ответ от ImgBB:', parsedData);
                                resolve(parsedData);
                            } catch (e) {
                                console.error('Ошибка парсинга ответа ImgBB:', e);
                                reject(e);
                            }
                        });
                    });

                    req.on('error', (error) => {
                        console.error('Ошибка запроса к ImgBB:', error);
                        reject(error);
                    });

                    req.write(postData.toString());
                    req.end();
                });

                if (!imgbbResponse.success) {
                    console.error('Ошибка от ImgBB:', imgbbResponse);
                    throw new Error('Ошибка при загрузке изображения на ImgBB');
                }

                imageUrl = imgbbResponse.data.url;
                console.log('Изображение успешно загружено:', imageUrl);
            } catch (error) {
                console.error('Ошибка при обработке изображения:', error);
                return res.status(500).json({ 
                    success: false,
                    error: 'Ошибка при загрузке изображения. Пожалуйста, попробуйте другое изображение или повторите попытку позже.'
                });
            }
        }

        // Создаем новый проект в базе данных
        console.log('Создаем запись в БД:', { 
            projects_title, 
            projects_description, 
            imageUrl, 
            is_dark_theme,
            is_dark_theme_value: is_dark_theme === 'true' ? 1 : 0
        });

        const insertQuery = 'INSERT INTO projects (projects_title, projects_description, projects_background, is_dark_theme) VALUES (?, ?, ?, ?)';
        
        db.query(insertQuery, [
            projects_title, 
            projects_description, 
            imageUrl, 
            is_dark_theme === 'true' ? 1 : 0
        ], (err, result) => {
            if (err) {
                console.error("Ошибка при создании проекта в БД:", err);
                return res.status(500).json({ 
                    success: false,
                    error: 'Ошибка при создании проекта в базе данных'
                });
            }
            
            console.log('Проект успешно создан:', result);
            res.json({ 
                success: true,
                message: 'Проект успешно создан',
                data: { 
                    id: result.insertId,
                    projects_title,
                    projects_description,
                    projects_background: imageUrl,
                    is_dark_theme: is_dark_theme === 'true'
                }
            });
        });
    } catch (error) {
        console.error("Ошибка при обработке запроса /projects:", error);
        res.status(500).json({ 
            success: false,
            error: 'Внутренняя ошибка сервера. Пожалуйста, попробуйте позже.'
        });
    }
});

// Обновление проекта
app.put('/projects/:id', upload.single('projects_background'), async (req, res) => {
    try {
        const { id } = req.params;
        const { projects_title, projects_description, is_dark_theme } = req.body;
        console.log('Обновление проекта:', { id, projects_title, projects_description, is_dark_theme });

        let imageUrl = null;

        // Если загружено новое изображение
        if (req.file) {
            // Конвертируем буфер в base64
            const base64Image = req.file.buffer.toString('base64');

            // Загружаем изображение на ImgBB
            const postData = new URLSearchParams();
            postData.append('image', base64Image);
            postData.append('key', process.env.IMGBB_API_KEY);

            const options = {
                hostname: 'api.imgbb.com',
                path: '/1/upload',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Content-Length': postData.toString().length
                }
            };

            const imgbbResponse = await new Promise((resolve, reject) => {
                const req = https.request(options, (res) => {
                    let data = '';
                    res.on('data', (chunk) => {
                        data += chunk;
                    });
                    res.on('end', () => {
                        try {
                            resolve(JSON.parse(data));
                        } catch (e) {
                            reject(e);
                        }
                    });
                });

                req.on('error', (error) => {
                    reject(error);
                });

                req.write(postData.toString());
                req.end();
            });

            if (!imgbbResponse.success) {
                throw new Error('Ошибка при загрузке изображения на ImgBB');
            }

            imageUrl = imgbbResponse.data.url;
        }

        // Формируем SQL запрос
        const updateFields = [];
        const updateValues = [];
        
        if (projects_title) {
            updateFields.push('projects_title = ?');
            updateValues.push(projects_title);
        }
        
        if (projects_description) {
            updateFields.push('projects_description = ?');
            updateValues.push(projects_description);
        }
        
        if (imageUrl) {
            updateFields.push('projects_background = ?');
            updateValues.push(imageUrl);
        }

        if (is_dark_theme !== undefined) {
            updateFields.push('is_dark_theme = ?');
            updateValues.push(is_dark_theme === 'true' ? 1 : 0);
        }

        // Если нет полей для обновления, возвращаем ошибку
        if (updateFields.length === 0) {
            return res.status(400).json({ error: 'Нет данных для обновления' });
        }

        // Добавляем id в конец массива значений
        updateValues.push(id);

        // Формируем финальный SQL запрос
        const updateQuery = `UPDATE projects SET ${updateFields.join(', ')} WHERE id = ?`;

        console.log('SQL Query:', updateQuery);
        console.log('Values:', updateValues);

        // Выполняем обновление
        db.query(updateQuery, updateValues, (err, result) => {
            if (err) {
                console.error("Ошибка при обновлении проекта:", err);
                return res.status(500).json({ error: 'Ошибка при обновлении проекта' });
            }
            res.json({ 
                success: true,
                message: 'Проект успешно обновлен',
                data: { 
                    id, 
                    projects_title, 
                    projects_description, 
                    projects_background: imageUrl,
                    is_dark_theme: is_dark_theme === 'true'
                }
            });
        });
    } catch (error) {
        console.error("Ошибка при обработке запроса /projects/:id:", error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Удаление проекта
app.delete('/projects/:id', async (req, res) => {
    try {
        const { id } = req.params;

        console.log('Получен запрос на удаление проекта:', { id });

        // Проверяем существование проекта
        const checkQuery = 'SELECT * FROM projects WHERE id = ?';
        const project = await new Promise((resolve, reject) => {
            db.query(checkQuery, [id], (err, results) => {
                if (err) {
                    console.error('Ошибка при проверке проекта:', err);
                    reject(err);
                } else {
                    resolve(results[0]);
                }
            });
        });

        if (!project) {
            console.log('Проект не найден:', { id });
            return res.status(404).json({
                success: false,
                error: 'Проект не найден'
            });
        }

        // Удаляем проект
        const deleteQuery = 'DELETE FROM projects WHERE id = ?';
        await new Promise((resolve, reject) => {
            db.query(deleteQuery, [id], (err, result) => {
                if (err) {
                    console.error('Ошибка при удалении проекта:', err);
                    reject(err);
                } else {
                    resolve(result);
                }
            });
        });

        console.log('Проект успешно удален:', { id });
        res.json({
            success: true,
            message: 'Проект успешно удален'
        });
    } catch (error) {
        console.error('Ошибка при обработке запроса на удаление:', error);
        res.status(500).json({
            success: false,
            error: 'Ошибка при удалении проекта'
        });
    }
});

// Обновление преимущества
app.put('/benefits/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { benefit_title, benefit_description } = req.body;
        console.log('Обновление преимущества:', { id, benefit_title, benefit_description });

        // Проверяем существование преимущества
        const checkQuery = 'SELECT * FROM benefits WHERE id = ?';
        const benefit = await new Promise((resolve, reject) => {
            db.query(checkQuery, [id], (err, results) => {
                if (err) {
                    console.error('Ошибка при проверке преимущества:', err);
                    reject(err);
                } else {
                    resolve(results[0]);
                }
            });
        });

        if (!benefit) {
            console.log('Преимущество не найдено:', { id });
            return res.status(404).json({
                success: false,
                error: 'Преимущество не найдено'
            });
        }

        // Формируем SQL запрос
        const updateFields = [];
        const updateValues = [];
        
        if (benefit_title) {
            updateFields.push('benefit_title = ?');
            updateValues.push(benefit_title);
        }
        
        if (benefit_description) {
            updateFields.push('benefit_description = ?');
            updateValues.push(benefit_description);
        }

        // Если нет полей для обновления, возвращаем ошибку
        if (updateFields.length === 0) {
            return res.status(400).json({ error: 'Нет данных для обновления' });
        }

        // Добавляем id в конец массива значений
        updateValues.push(id);

        // Формируем финальный SQL запрос
        const updateQuery = `UPDATE benefits SET ${updateFields.join(', ')} WHERE id = ?`;

        console.log('SQL Query:', updateQuery);
        console.log('Values:', updateValues);

        // Выполняем обновление
        db.query(updateQuery, updateValues, (err, result) => {
            if (err) {
                console.error("Ошибка при обновлении преимущества:", err);
                return res.status(500).json({ error: 'Ошибка при обновлении преимущества' });
            }
            res.json({ 
                success: true,
                message: 'Преимущество успешно обновлено',
                data: { 
                    id, 
                    benefit_title, 
                    benefit_description
                }
            });
        });
    } catch (error) {
        console.error("Ошибка при обработке запроса /benefits/:id:", error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Удаление преимущества
app.delete('/benefits/:id', async (req, res) => {
    try {
        const { id } = req.params;

        console.log('Получен запрос на удаление преимущества:', { id });

        // Проверяем существование преимущества
        const checkQuery = 'SELECT * FROM benefits WHERE id = ?';
        const benefit = await new Promise((resolve, reject) => {
            db.query(checkQuery, [id], (err, results) => {
                if (err) {
                    console.error('Ошибка при проверке преимущества:', err);
                    reject(err);
                } else {
                    resolve(results[0]);
                }
            });
        });

        if (!benefit) {
            console.log('Преимущество не найдено:', { id });
            return res.status(404).json({
                success: false,
                error: 'Преимущество не найдено'
            });
        }

        // Удаляем преимущество
        const deleteQuery = 'DELETE FROM benefits WHERE id = ?';
        await new Promise((resolve, reject) => {
            db.query(deleteQuery, [id], (err, result) => {
                if (err) {
                    console.error('Ошибка при удалении преимущества:', err);
                    reject(err);
                } else {
                    resolve(result);
                }
            });
        });

        console.log('Преимущество успешно удалено:', { id });
        res.json({
            success: true,
            message: 'Преимущество успешно удалено'
        });
    } catch (error) {
        console.error('Ошибка при обработке запроса на удаление:', error);
        res.status(500).json({
            success: false,
            error: 'Ошибка при удалении преимущества'
        });
    }
});

// Получение всех заказов с детальной информацией
app.get('/site-orders', async (req, res) => {
    try {
        const query = `
            SELECT o.*, 
                   s.title as service_title,
                   e.full_name as executor_name,
                   os.status_name as status
            FROM orders o
            LEFT JOIN services s ON o.service_id = s.id
            LEFT JOIN executors e ON o.executor_id = e.id
            LEFT JOIN order_statuses os ON o.status_id = os.id
        `;

        db.query(query, (error, results) => {
            if (error) {
                console.error('Ошибка при получении заказов:', error);
                return res.status(500).json({ error: 'Ошибка при получении заказов' });
            }
            res.json(results);
        });
    } catch (error) {
        console.error('Ошибка при обработке запроса:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// Получение детальной информации о конкретном заказе
app.get('/site-orders/:id', async (req, res) => {
    try {
        const orderId = req.params.id;
        const query = `
            SELECT 
                o.*,
                s.title as service_name,
                st.name as template_name,
                os.status_name,
                e.fullname as executor_name,
                u.username as customer_name,
                GROUP_CONCAT(sa.name) as addons
            FROM orders o
            LEFT JOIN services s ON o.services_id = s.id
            LEFT JOIN service_templates st ON o.template_id = st.id
            LEFT JOIN order_statuses os ON o.status_id = os.id
            LEFT JOIN executors e ON o.executor_id = e.id
            LEFT JOIN user u ON o.user_id = u.id
            LEFT JOIN order_addons oa ON o.id = oa.order_id
            LEFT JOIN service_addons sa ON oa.addon_id = sa.id
            WHERE o.id = ?
            GROUP BY o.id
        `;

        db.query(query, [orderId], (err, results) => {
            if (err) {
                console.error('Ошибка при получении заказа:', err);
                return res.status(500).json({ error: 'Ошибка при получении заказа' });
            }
            if (results.length === 0) {
                return res.status(404).json({ error: 'Заказ не найден' });
            }
            res.json(results[0]);
        });
    } catch (error) {
        console.error('Ошибка при обработке запроса:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// Получение статистики по заказам
app.get('/site-orders-stats', async (req, res) => {
    try {
        const query = `
            SELECT 
                COUNT(*) as total_orders,
                SUM(CASE WHEN status_id = 1 THEN 1 ELSE 0 END) as new_orders,
                SUM(CASE WHEN status_id = 2 THEN 1 ELSE 0 END) as in_progress_orders,
                SUM(CASE WHEN status_id = 3 THEN 1 ELSE 0 END) as completed_orders,
                AVG(price) as average_price,
                SUM(price) as total_revenue
            FROM orders
        `;

        db.query(query, (err, results) => {
            if (err) {
                console.error('Ошибка при получении статистики:', err);
                return res.status(500).json({ error: 'Ошибка при получении статистики' });
            }
            res.json(results[0]);
        });
    } catch (error) {
        console.error('Ошибка при обработке запроса:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// Получение всех дополнительных услуг
app.get('/service_addons', (req, res) => {
    const query = `
        SELECT 
            id,
            name,
            description,
            price,
            is_active
        FROM service_addons
        WHERE is_active = 1
    `;

    db.query(query, (err, results) => {
        if (err) {
            console.error('Ошибка при получении доп. услуг:', err);
            return res.status(500).json({ error: 'Ошибка при получении доп. услуг' });
        }
        res.json({ data: results });
    });
});

// Создание таблицы templates, если она не существует
const createTemplatesTable = `
    CREATE TABLE IF NOT EXISTS templates (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        preview_url VARCHAR(255),
        site_type VARCHAR(50) NOT NULL,
        price DECIMAL(10, 2) NOT NULL,
        service_id INT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (service_id) REFERENCES service(id)
    )
`;

db.query(createTemplatesTable, (err) => {
    if (err) {
        console.error('Ошибка при создании таблицы templates:', err);
    } else {
        console.log('Таблица templates создана или уже существует');
    }
});

// Обновление service_id для всех шаблонов
const updateTemplatesServiceId = `
    UPDATE templates 
    SET service_id = 1 
    WHERE service_id IS NULL
`;

db.query(updateTemplatesServiceId, (err) => {
    if (err) {
        console.error('Ошибка при обновлении service_id для шаблонов:', err);
    } else {
        console.log('service_id обновлен для всех шаблонов');
    }
});

// Получение шаблонов сайтов
app.get('/templates', (req, res) => {
    const { service_id } = req.query;
    
    let query = `
        SELECT 
            t.id,
            t.name,
            t.description,
            t.preview_url,
            t.site_type,
            t.price,
            t.service_id
        FROM templates t
    `;

    const queryParams = [];

    if (service_id) {
        query += ' WHERE t.service_id = ?';
        queryParams.push(service_id);
    }

    query += ' ORDER BY t.site_type, t.name';

    db.query(query, queryParams, (err, results) => {
        if (err) {
            console.error('Ошибка при получении шаблонов:', err);
            return res.status(500).json({ error: 'Ошибка при получении шаблонов' });
        }
        console.log('Получены шаблоны:', results);
        res.json({ data: results });
    });
});

// Получение цен на услуги
app.get('/service_pricing', (req, res) => {
    const query = `
        SELECT 
            service_type,
            base_price,
            price_per_block,
            min_blocks,
            max_blocks
        FROM service_pricing
        WHERE is_active = 1
    `;

    db.query(query, (err, results) => {
        if (err) {
            console.error('Ошибка при получении цен:', err);
            return res.status(500).json({ error: 'Ошибка при получении цен' });
        }
        res.json({ data: results });
    });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Сервер запущен на порту ${PORT}`);
});

// Функция для загрузки изображения на ImgBB
async function uploadToImgBB(imageBuffer) {
    try {
        const formData = new URLSearchParams();
        formData.append('image', imageBuffer.toString('base64'));
        formData.append('key', process.env.IMGBB_API_KEY);

        const response = await fetch('https://api.imgbb.com/1/upload', {
            method: 'POST',
            body: formData,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });

        if (!response.ok) {
            throw new Error('Ошибка при загрузке изображения на ImgBB');
        }

        const data = await response.json();
        return data.data.url;
    } catch (error) {
        console.error('Ошибка при загрузке изображения:', error);
        throw error;
    }
}

