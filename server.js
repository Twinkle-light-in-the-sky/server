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
const { Storage } = require('megajs');

// Загружаем переменные окружения
require('dotenv').config();

// Инициализация MEGA клиента
const megaStorage = new Storage({
    email: process.env.MEGA_EMAIL,
    password: process.env.MEGA_PASSWORD
});

// Добавляем обработку ошибок инициализации MEGA
megaStorage.on('ready', () => {
    console.log('MEGA клиент успешно инициализирован');
}).on('error', (err) => {
    console.error('Ошибка инициализации MEGA клиента:', err);
});

// Функция для загрузки файла на MEGA
async function uploadToMega(fileBuffer, fileName) {
    try {
        if (!megaStorage.ready) {
            await new Promise((resolve, reject) => {
                megaStorage.once('ready', resolve);
                megaStorage.once('error', reject);
            });
        }

        console.log('Начинаем загрузку файла на MEGA:', fileName);
        const uploadStream = megaStorage.upload(fileName, fileBuffer);
        
        await new Promise((resolve, reject) => {
            uploadStream.on('complete', resolve);
            uploadStream.on('error', reject);
        });

        console.log('Файл успешно загружен, получаем ссылку');
        const filesArr = Object.values(megaStorage.files);
        const file = filesArr.find(f => f.name === fileName);
        
        if (!file) {
            throw new Error('Файл не найден после загрузки');
        }

        const fileLink = await file.link();
        console.log('Ссылка на файл получена:', fileLink);
        return fileLink;
    } catch (error) {
        console.error('Ошибка при загрузке на MEGA:', error);
        throw new Error(`Ошибка загрузки на MEGA: ${error.message}`);
    }
}

// Функция для получения файла с MEGA
async function getFromMega(fileId) {
    try {
        await megaStorage.ready;
        const file = await megaStorage.find(fileId);
        if (!file) {
            throw new Error('Файл не найден');
        }
        return await file.download();
    } catch (error) {
        console.error('Ошибка при получении файла с MEGA:', error);
        throw error;
    }
}

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
const allowedMimeTypes = [
    'image/',
    'application/zip',
    'application/x-zip-compressed',
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/x-rar-compressed',
    'application/x-7z-compressed',
    'image/vnd.adobe.photoshop',
    'application/octet-stream', // для некоторых нестандартных файлов
    'application/x-fig',
    'application/x-sketch',
    'application/vnd.adobe.xd',
    'application/postscript',
    'image/svg+xml'
];

const fileFilter = (req, file, cb) => {
    if (
        file.mimetype.startsWith('image/') ||
        allowedMimeTypes.includes(file.mimetype)
    ) {
        cb(null, true);
    } else {
        cb(new Error('Неверный тип файла. Разрешены только изображения, zip, pdf, doc, docx, rar, 7z, psd, fig, sketch, xd, ai, eps, svg.'), false);
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
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'Origin', 'X-Requested-With', 'X-HTTP-Method-Override'],
    exposedHeaders: ['Content-Range', 'X-Content-Range'],
    credentials: true,
    maxAge: 86400,
    preflightContinue: false,
    optionsSuccessStatus: 204
};

const app = express();

// Добавляем middleware для логирования CORS
app.use((req, res, next) => {
    console.log('CORS Request:', {
        origin: req.headers.origin,
        method: req.method,
        path: req.path,
        headers: req.headers
    });
    next();
});

app.use(cors(corsOptions));

// Обработка preflight запросов
app.options('*', cors(corsOptions));

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

    console.log('Проверка токена:', {
        hasAuthHeader: !!authHeader,
        token: token ? 'Present' : 'Missing',
        headers: req.headers,
        method: req.method,
        path: req.path,
        url: req.url
    });

  if (!token) {
    console.log('Токен отсутствует в заголовке');
    return res.status(401).json({ message: 'Токен не найден' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) {
      console.log('Ошибка верификации токена:', err);
      return res.status(403).json({ message: 'Недействительный токен' });
    }
        console.log('Токен верифицирован, пользователь:', user);
    req.user = user;
    next();
  });
};

app.post('/regpage', express.json({ limit: '32mb' }), bodyParser.json({ limit: '32mb' }), express.urlencoded({ extended: true, limit: '32mb' }), bodyParser.urlencoded({ extended: true, limit: '32mb' }), async (req, res) => {
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

app.post('/logpage', express.json({ limit: '32mb' }), bodyParser.json({ limit: '32mb' }), express.urlencoded({ extended: true, limit: '32mb' }), bodyParser.urlencoded({ extended: true, limit: '32mb' }), async (req, res) => {
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
            db.query('SELECT id, projects_title, projects_description, projects_background, is_dark_theme, link, block_size FROM projects ORDER BY id ASC', (err, results) => {
                if (err) {
                    console.error('Ошибка при получении проектов:', err);
                    reject(err);
                } else {
                    const formattedResults = results.map(project => ({
                        ...project,
                        is_dark_theme: Boolean(project.is_dark_theme)
                    }));
                    resolve(formattedResults);
                }
            });
        });
        console.log('Найдено проектов:', projects.length);
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
            res.json(results);
        });
    } catch (error) {
        console.error("Ошибка при обработке запроса /benefits:", error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/orderstatuses', async (req, res) => {
    try {
        console.log('Получен запрос на получение статусов заказов');
        
        const getStatusesQuery = 'SELECT * FROM order_statuses';
        db.query(getStatusesQuery, (err, results) => {
            if (err) {
                console.error("Ошибка при получении статусов:", err);
                return res.status(500).json({ error: 'Ошибка при получении данных' });
            }
            
            console.log('Отправка статусов заказов:', results);
            res.json(results);
        });
    } catch (error) {
        console.error("Ошибка при обработке запроса /orderstatuses:", error);
        res.status(500).json({ error: 'Ошибка сервера' });
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

// Создание нового преимущества
app.post('/benefits', express.json(), (req, res) => {
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

app.post('/createOrder', authenticateToken, upload.fields([
    { name: 'files', maxCount: 5 },
    { name: 'template_file', maxCount: 1 }
]), async (req, res) => {
    try {
        console.log('Получен запрос на создание заказа:', req.body);

        // Парсим selected_addons, если это строка
        let selected_addons = req.body.selected_addons;
        if (typeof selected_addons === 'string') {
            try {
                selected_addons = JSON.parse(selected_addons);
            } catch (e) {
                selected_addons = [];
            }
        }

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
            console.error('Отсутствуют обязательные поля:', {
                project_name,
                user_id,
                service_id,
                executor_id,
                status_id,
                order_date
            });
            return res.status(400).json({
                success: false,
                message: 'Не все обязательные поля заполнены'
            });
        }

        // Проверяем существование шаблона в таблице templates
        const checkTemplateQuery = 'SELECT * FROM templates WHERE id = ?';
        const [template] = await new Promise((resolve, reject) => {
            db.query(checkTemplateQuery, [template_id], (err, results) => {
                if (err) {
                    console.error('Ошибка при проверке шаблона:', err);
                    reject(err);
                } else {
                    resolve(results);
                }
            });
        });

        if (!template) {
            return res.status(400).json({
                success: false,
                message: 'Указанный шаблон не существует'
            });
        }

        // --- ДОБАВЛЯЕМ ЗАГРУЗКУ ФАЙЛА ШАБЛОНА НА MEGA ---
        let templateFileUrl = null;
        if (req.files && req.files['template_file'] && req.files['template_file'][0]) {
            try {
                const file = req.files['template_file'][0];
                console.log('Пробуем загрузить файл на MEGA:', file.originalname, file.buffer.length);
                templateFileUrl = await uploadToMega(file.buffer, file.originalname);
                console.log('Файл успешно загружен на MEGA:', templateFileUrl);
            } catch (err) {
                console.error('Ошибка при загрузке файла шаблона на MEGA:', err);
                return res.status(500).json({
                    success: false,
                    message: 'Ошибка при загрузке файла шаблона'
                });
            }
        }
        // --- КОНЕЦ ДОБАВЛЕНИЯ ---

        // Создаем заказ
        const insertQuery = `
            INSERT INTO orders (
                project_name, user_id, service_id, template_id, 
                site_type, blocks_count, price, additional_info,
                need_receipt, status_id, executor_id, order_date, template_file_url
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;

        const values = [
            project_name,
            user_id,
            service_id,
            template_id,
            site_type,
            blocks_count,
            price,
            additional_info,
            need_receipt ? 1 : 0,
            status_id,
            executor_id,
            order_date,
            templateFileUrl
        ];

        console.log('Подготовленные значения для вставки:', values);

        const result = await new Promise((resolve, reject) => {
            db.query(insertQuery, values, (err, result) => {
                if (err) {
                    console.error('Ошибка при создании заказа:', err);
                    reject(err);
                } else {
                    resolve(result);
                }
            });
        });

        // Добавляем запись в историю статусов
        const historyQuery = `
            INSERT INTO order_status_history (order_id, status_id, comment) 
            VALUES (?, ?, 'Заказ создан')
        `;

        await new Promise((resolve, reject) => {
            db.query(historyQuery, [result.insertId, status_id], (err) => {
                if (err) {
                    console.error('Ошибка при добавлении в историю:', err);
                    reject(err);
                } else {
                    resolve();
                }
            });
        });

        res.json({
            success: true,
            orderId: result.insertId,
            template_file_url: templateFileUrl,
            message: 'Заказ успешно создан'
        });

        // === ДОБАВЛЯЕМ ДОПОЛНИТЕЛЬНЫЕ УСЛУГИ ===
        if (Array.isArray(selected_addons) && selected_addons.length > 0) {
            const addonValues = selected_addons.map(addonId => [result.insertId, addonId]);
            db.query(
                'INSERT INTO order_addons (order_id, addon_id) VALUES ?',
                [addonValues],
                (err, res2) => {
                    if (err) {
                        console.error('Ошибка при добавлении дополнительных услуг:', err);
                    } else {
                        console.log('Дополнительные услуги успешно добавлены:', res2);
                    }
                }
            );
        }
        // === КОНЕЦ ДОБАВЛЕНИЯ ДОП.УСЛУГ ===
    } catch (error) {
        console.error('Ошибка при обработке запроса:', error);
        res.status(500).json({
            success: false,
            message: 'Внутренняя ошибка сервера',
            error: error.message, // Показываем текст ошибки
            stack: error.stack    // (по желанию) Показываем стек вызова
        });
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
                   os.status_name,
                   u.username as customer_name
            FROM orders o
            LEFT JOIN services s ON o.service_id = s.id
            LEFT JOIN executors e ON o.executor_id = e.id
            LEFT JOIN order_statuses os ON o.status_id = os.id
            LEFT JOIN user u ON o.user_id = u.id
            WHERE o.user_id = ?
        `;
        db.query(getOrdersQuery, [userId], (err, results) => {
            if (err) {
                console.error("Ошибка при получении заказов:", err);
                return res.status(500).json({ error: 'Ошибка при получении данных' });
            }
            console.log("Полученные заказы для пользователя:", userId, results);
            // CORS fix
            const origin = req.headers.origin;
            const allowedOrigins = [
                'http://localhost:3000',
                'http://localhost:3001',
                'https://barsikec.beget.tech',
                'http://barsikec.beget.tech',
                'https://startset-app.vercel.app',
                'https://server-9va8.onrender.com'
            ];
            if (origin && allowedOrigins.includes(origin)) {
                res.header('Access-Control-Allow-Origin', origin);
                res.header('Access-Control-Allow-Credentials', 'true');
            }
            res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
            res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
            res.json(results);
        });
    } catch (error) {
        console.error("Ошибка при обработке запроса /orders:", error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Эндпоинт для загрузки аватара
app.post('/upload-avatar', authenticateToken, express.json({ limit: '32mb' }), async (req, res) => {
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
app.put('/updateprofile', authenticateToken, express.json({ limit: '32mb' }), async (req, res) => {
  try {
    console.log('Получен запрос на обновление профиля:', req.body);
    const userId = req.user.id;
    const { username, email, phone, address, coordinates } = req.body;

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

    if (coordinates !== undefined) {
      updateFields.push('coordinates = ?');
      updateValues.push(JSON.stringify(coordinates));
    }

    // Если нет полей для обновления, возвращаем ошибку
    if (updateFields.length === 0) {
      return res.status(400).json({ error: 'Нет данных для обновления' });
    }

    // Добавляем id в конец массива значений
    updateValues.push(userId);

    // Формируем финальный SQL запрос
    const updateQuery = `UPDATE user SET ${updateFields.join(', ')} WHERE id = ?`;

    console.log('SQL Query:', updateQuery);
    console.log('Values:', updateValues);

    // Выполняем обновление
    await new Promise((resolve, reject) => {
      db.query(updateQuery, updateValues, (error, results) => {
        if (error) {
          console.error('Ошибка при обновлении данных пользователя:', error);
          reject(error);
        }
        resolve(results);
      });
    });

    // Получаем обновленного пользователя
    const [updatedUser] = await new Promise((resolve, reject) => {
      db.query('SELECT id, username, email, phone, address, avatar, role, coordinates FROM user WHERE id = ?', [userId], (error, results) => {
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
    console.error('Server Error:', err);
    res.status(500).json({
        error: 'Internal Server Error',
        message: err.message
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
        
        console.log('Получен запрос на обновление услуги:', {
            id,
            title,
            description,
            is_dark_theme,
            hasFile: !!req.file
        });

        let imageUrl = null;

        // Если загружено новое изображение
        if (req.file) {
            console.log('Обработка нового изображения:', {
                originalname: req.file.originalname,
                mimetype: req.file.mimetype,
                size: req.file.size
            });

            try {
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

                console.log('Отправка запроса к ImgBB API');
                const imgbbResponse = await new Promise((resolve, reject) => {
                    const req = https.request(options, (res) => {
                        let data = '';
                        res.on('data', (chunk) => {
                            data += chunk;
                        });
                        res.on('end', () => {
                            try {
                                const parsedData = JSON.parse(data);
                                console.log('Ответ от ImgBB:', parsedData);
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
            return res.status(400).json({ 
                success: false,
                error: 'Нет данных для обновления' 
            });
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
                return res.status(500).json({ 
                    success: false,
                    error: 'Ошибка при обновлении услуги' 
                });
            }

            if (result.affectedRows === 0) {
                return res.status(404).json({ 
                    success: false,
                    error: 'Услуга не найдена' 
                });
            }

            console.log('Услуга успешно обновлена:', {
                id,
                affectedRows: result.affectedRows
            });

            res.json({ 
                success: true,
                message: 'Услуга успешно обновлена',
                data: { 
                    id, 
                    title, 
                    description, 
                    background_image: imageUrl,
                    is_dark_theme: is_dark_theme === 'true'
                }
            });
        });
    } catch (error) {
        console.error("Ошибка при обработке запроса /services/:id:", error);
        res.status(500).json({ 
            success: false,
            error: 'Ошибка сервера' 
        });
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
        console.log('Received project data:', req.body); // Добавляем для отладки
        
        const { projects_title, projects_description, is_dark_theme, link, block_size } = req.body;
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
            link,
            block_size
        });

        const insertQuery = 'INSERT INTO projects (projects_title, projects_description, projects_background, is_dark_theme, link, block_size) VALUES (?, ?, ?, ?, ?, ?)';
        
        db.query(insertQuery, [
            projects_title, 
            projects_description, 
            imageUrl, 
            is_dark_theme === 'true' ? 1 : 0,
            link || '',
            block_size || 'col-6'
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
                    is_dark_theme: is_dark_theme === 'true',
                    link: link || '',
                    block_size: block_size || 'col-6'
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
        const { projects_title, projects_description, is_dark_theme, link, block_size } = req.body;
        console.log('Обновление проекта:', { id, projects_title, projects_description, is_dark_theme, link, block_size });

        let imageUrl = null;

        // Если загружено новое изображение
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

        if (link !== undefined) {
            updateFields.push('link = ?');
            updateValues.push(link);
        }

        if (block_size !== undefined) {
            updateFields.push('block_size = ?');
            updateValues.push(block_size);
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
                    is_dark_theme: is_dark_theme === 'true',
                    block_size
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
app.put('/benefits/:id', express.json(), async (req, res) => {
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
                e.fullname as executor_name,
                os.status_name as status,
                u.username as customer_name
            FROM orders o
            LEFT JOIN services s ON o.service_id = s.id
            LEFT JOIN executors e ON o.executor_id = e.id
            LEFT JOIN order_statuses os ON o.status_id = os.id
            LEFT JOIN user u ON o.user_id = u.id
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
    const { service_id } = req.query;
    let query = 'SELECT * FROM service_addons WHERE is_active = 1';
    const params = [];
    
    if (service_id) {
        query += ' AND service_id = ?';
        params.push(service_id);
    }
    
    db.query(query, params, (err, results) => {
        if (err) {
            console.error('Ошибка при получении доп. услуг:', err);
            return res.status(500).json({ 
                success: false,
                message: 'Ошибка при получении дополнительных услуг',
                error: err.message 
            });
        }
        res.json({
            success: true,
            data: results
        });
    });
});

// Получение шаблонов сайтов
app.get('/templates', (req, res) => {
    const { service_id } = req.query;
    
    console.log('Получен запрос на шаблоны:', { service_id });
    
    let query = 'SELECT * FROM templates';
    const params = [];
    
    if (service_id) {
        query += ' WHERE service_id = ?';
        params.push(service_id);
    }
    
    console.log('Выполняется запрос:', { query, params });
    
    // Добавляем CORS-заголовки
    const origin = req.headers.origin;
    if (origin && ['http://localhost:3000', 'http://localhost:3001', 'https://barsikec.beget.tech', 'http://barsikec.beget.tech', 'https://startset-app.vercel.app', 'https://server-9va8.onrender.com'].includes(origin)) {
        res.header('Access-Control-Allow-Origin', origin);
        res.header('Access-Control-Allow-Credentials', 'true');
    }
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Accept, Origin, X-Requested-With');
    
    db.query(query, params, (err, results) => {
        if (err) {
            console.error('Ошибка при получении шаблонов:', err);
            return res.status(500).json({ 
                success: false,
                message: 'Ошибка при получении шаблонов',
                error: err.message
            });
        }
        
        console.log('Получены шаблоны:', results);
        res.json({
            success: true,
            data: results
        });
    });
});

// Получение цен на услуги
app.get('/service_pricing', (req, res) => {
    const { service_id } = req.query;
    let query = `
        SELECT 
            id,
            service_id,
            base_price,
            price_per_block,
            min_blocks,
            max_blocks,
            is_active,
            type
        FROM service_pricing
        WHERE is_active = 1
    `;
    const params = [];
    if (service_id) {
        query += ' AND service_id = ?';
        params.push(service_id);
    }

    db.query(query, params, (err, results) => {
        if (err) {
            console.error('Ошибка при получении цен:', err);
            return res.status(500).json({ error: 'Ошибка при получении цен' });
        }
        res.json({ data: results });
    });
});




// Создание заказа с дополнительными услугами
app.post('/orders', (req, res) => {
    const { 
        project_name, 
        site_type, 
        blocks_count, 
        template_name, 
        service_id, 
        user_id, 
        additional_info, 
        need_receipt, 
        price,
        selected_addons 
    } = req.body;

    // Проверяем существование пользователя
    const checkUserQuery = 'SELECT id FROM user WHERE id = ?';
    db.query(checkUserQuery, [user_id], (err, results) => {
        if (err) {
            console.error('Ошибка при проверке пользователя:', err);
            return res.status(500).json({ error: 'Ошибка сервера' });
        }
        
        if (results.length === 0) {
            return res.status(400).json({ error: 'Пользователь не найден' });
        }

        const orderQuery = `
            INSERT INTO orders (
                project_name, 
                site_type, 
                blocks_count, 
                template_name, 
                service_id, 
                user_id, 
                additional_info, 
                need_receipt, 
                price, 
                order_date, 
                status_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURDATE(), 1)
        `;

        const orderValues = [
            project_name, 
            site_type, 
            blocks_count, 
            template_name, 
            service_id, 
            user_id, 
            additional_info, 
            need_receipt, 
            price
        ];

        db.query(orderQuery, orderValues, (err, result) => {
            if (err) {
                console.error('Ошибка при создании заказа:', err);
                return res.status(500).json({ error: 'Ошибка сервера' });
            }

            const orderId = result.insertId;

            // Если есть выбранные доп. услуги, добавляем их
            if (selected_addons && selected_addons.length > 0) {
                const addonQuery = `
                    INSERT INTO order_addons (order_id, addon_id, price_at_time) 
                    SELECT ?, id, price 
                    FROM service_addons 
                    WHERE id IN (?)
                `;

                db.query(addonQuery, [orderId, selected_addons], (err, result) => {
                    if (err) {
                        console.error('Ошибка при добавлении дополнительных услуг:', err);
                        return res.status(500).json({ error: 'Ошибка при добавлении дополнительных услуг' });
                    }
                    res.json({
                        success: true,
                        orderId: orderId,
                        message: 'Заказ успешно создан с дополнительными услугами'
                    });
                });
            } else {
                res.json({
                    success: true,
                    orderId: orderId,
                    message: 'Заказ успешно создан'
                });
            }
        });
    });
});

// Эндпоинт для удаления заказа
app.delete('/orders/:orderId', authenticateToken, (req, res) => {
    const orderId = req.params.orderId;
    const userId = req.user.id;
    const userRole = req.user.role;

    // Если админ — ищем только по id, если обычный — по id и user_id
    const query = userRole === 'admin'
        ? 'SELECT * FROM orders WHERE id = ?'
        : 'SELECT * FROM orders WHERE id = ? AND user_id = ?';
    const params = userRole === 'admin'
        ? [orderId]
        : [orderId, userId];

    db.query(
        query,
        params,
        (err, rows) => {
            if (err) {
                console.error('Ошибка при проверке заказа:', err);
                return res.status(500).json({
                    success: false,
                    error: 'Ошибка при проверке заказа',
                    details: err.message
                });
            }

            if (!rows || rows.length === 0) {
                console.log(`Заказ ${orderId} не найден или нет прав на удаление (роль: ${userRole})`);
                return res.status(404).json({
                    success: false,
                    error: 'Заказ не найден или у вас нет прав на его удаление'
                });
            }

            console.log(`Начинаем удаление заказа ${orderId}`);

            // Сначала удаляем все доп.услуги этого заказа
            db.query(
                'DELETE FROM order_addons WHERE order_id = ?',
                [orderId],
                (err, result) => {
                    if (err) {
                        console.error('Ошибка при удалении доп.услуг:', err);
                        return res.status(500).json({
                            success: false,
                            error: 'Ошибка при удалении доп.услуг',
                            details: err.message
                        });
                    }

                    // Затем удаляем записи из истории статусов
                    db.query(
                        'DELETE FROM order_status_history WHERE order_id = ?',
                        [orderId],
                        (err, result) => {
                            if (err) {
                                console.error('Ошибка при удалении истории статусов:', err);
                                return res.status(500).json({
                                    success: false,
                                    error: 'Ошибка при удалении истории заказа',
                                    details: err.message
                                });
                            }

                            // Затем удаляем сам заказ
                            db.query(
                                'DELETE FROM orders WHERE id = ?',
                                [orderId],
                                (err, result) => {
                                    if (err) {
                                        console.error('Ошибка при удалении заказа:', err);
                                        return res.status(500).json({
                                            success: false,
                                            error: 'Ошибка при удалении заказа',
                                            details: err.message
                                        });
                                    }

                                    if (result.affectedRows > 0) {
                                        console.log(`Заказ ${orderId} успешно удален`);
                                        res.json({
                                            success: true,
                                            message: 'Заказ успешно удален'
                                        });
                                    } else {
                                        console.log(`Не удалось удалить заказ ${orderId}`);
                                        res.status(404).json({
                                            success: false,
                                            error: 'Не удалось удалить заказ'
                                        });
                                    }
                                }
                            );
                        }
                    );
                }
            );
        }
    );
});

// Эндпоинт для отмены заказа
app.put('/orders/:orderId/cancel', authenticateToken, (req, res) => {
    const orderId = req.params.orderId;
    const userId = req.user.id;
    const userRole = req.user.role;

    console.log('DEBUG ОТМЕНА ЗАКАЗА:', { orderId, userId, userRole });

    // Если админ — ищем только по id, если обычный — по id и user_id
    const query = userRole === 'admin'
        ? 'SELECT * FROM orders WHERE id = ?'
        : 'SELECT * FROM orders WHERE id = ? AND user_id = ?';
    const params = userRole === 'admin'
        ? [orderId]
        : [orderId, userId];

    console.log('DEBUG SQL:', { query, params });

    db.query(
        query,
        params,
        (err, rows) => {
            if (err) {
                console.error('Ошибка при проверке заказа:', err);
                return res.status(500).json({
                    success: false,
                    error: 'Ошибка при проверке заказа',
                    details: err.message
                });
            }

            if (!rows || rows.length === 0) {
                console.log(`Заказ ${orderId} не найден или не принадлежит пользователю ${userId}`);
                return res.status(404).json({
                    success: false,
                    error: 'Заказ не найден или у вас нет прав на его отмену'
                });
            }

            // Обновляем статус заказа
            db.query(
                'UPDATE orders SET status_id = 8 WHERE id = ?',
                [orderId],
                (err, result) => {
                    if (err) {
                        console.error('Ошибка при отмене заказа:', err);
                        return res.status(500).json({
                            success: false,
                            error: 'Ошибка при отмене заказа',
                            details: err.message
                        });
                    }

                    if (result.affectedRows > 0) {
                        console.log(`Заказ ${orderId} успешно отменен`);
                        res.json({
                            success: true,
                            message: 'Заказ успешно отменен'
                        });
                    } else {
                        console.log(`Не удалось отменить заказ ${orderId}`);
                        res.status(404).json({
                            success: false,
                            error: 'Не удалось отменить заказ'
                        });
                    }
                }
            );
        }
    );
});

app.put('/orders/:orderId/status', authenticateToken, express.json(), async (req, res) => {
    try {
        const orderId = req.params.orderId;
        const { status_id } = req.body;

        if (!status_id) {
            return res.status(400).json({ success: false, message: 'Не передан статус' });
        }

        // Обновляем статус заказа
        await new Promise((resolve, reject) => {
            db.query(
                'UPDATE orders SET status_id = ? WHERE id = ?',
                [status_id, orderId],
                (err, result) => {
                    if (err) return reject(err);
                    resolve(result);
                }
            );
        });

        // Добавляем запись в историю статусов
        await new Promise((resolve, reject) => {
            db.query(
                'INSERT INTO order_status_history (order_id, status_id, comment) VALUES (?, ?, ?)',
                [orderId, status_id, 'Статус изменён администратором'],
                (err) => {
                    if (err) return reject(err);
                    resolve();
                }
            );
        });

        res.json({ success: true, message: 'Статус заказа обновлён' });
    } catch (error) {
        console.error('Ошибка при обновлении статуса заказа:', error);
        res.status(500).json({ success: false, message: 'Ошибка сервера' });
    }
});

// Эндпоинт для загрузки оверлея проекта (только для админа)
app.post('/orders/:orderId/upload-overlay', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        // Проверка роли (только админ)
        if (!req.user || req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Доступ запрещён' });
        }
        const orderId = req.params.orderId;
        if (!req.file) {
            console.log('Файл не был получен!');
            return res.status(400).json({ success: false, message: 'Файл не загружен' });
        }
        // Безопасный вывод информации о файле
        console.log('Файл получен:', {
            originalname: req.file.originalname,
            size: req.file.size,
            mimetype: req.file.mimetype
        });
        const base64Image = req.file.buffer.toString('base64');
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
            const req2 = https.request(options, (res2) => {
                let data = '';
                res2.on('data', (chunk) => { data += chunk; });
                res2.on('end', () => {
                    try { resolve(JSON.parse(data)); }
                    catch (e) { reject(e); }
                });
            });
            req2.on('error', (error) => { reject(error); });
            req2.write(postData.toString());
            req2.end();
        });

        if (!imgbbResponse.success) {
            throw new Error('Ошибка при загрузке изображения на ImgBB');
        }

        const imageUrl = imgbbResponse.data.url;

        // Сохраняем ссылку в заказе
        await new Promise((resolve, reject) => {
            db.query(
                'UPDATE orders SET project_overlay_image = ? WHERE id = ?',
                [imageUrl, orderId],
                (err) => {
                    if (err) return reject(err);
                    resolve();
                }
            );
        });

        res.json({ success: true, imageUrl });
    } catch (error) {
        console.error('Ошибка при загрузке оверлея проекта:', error);
        res.status(500).json({ success: false, message: 'Ошибка сервера' });
    }
});

// Получить сообщения чата
app.get('/chats/:chatId/messages', (req, res) => {
    const chatId = req.params.chatId;
    db.query(
        'SELECT * FROM messages WHERE chat_id = ? ORDER BY timestamp ASC',
        [chatId],
        (err, results) => {
            if (err) {
                console.error('Ошибка при получении сообщений:', err);
                return res.status(500).json({ error: 'Ошибка при получении сообщений' });
            }
            res.json(results);
        }
    );
});

// Отправить сообщение
app.post('/chats/:chatId/messages', express.json(), (req, res) => {
    console.log('POST /chats/:chatId/messages HEADERS:', req.headers);
    console.log('POST /chats/:chatId/messages BODY:', req.body);
    const chatId = req.params.chatId;
    const { text, sender_id } = req.body;
    if (!text || !sender_id) {
        return res.status(400).json({ error: 'Текст и sender_id обязательны' });
    }
    db.query(
        'INSERT INTO messages (chat_id, sender_id, text) VALUES (?, ?, ?)',
        [chatId, sender_id, text],
        (err, result) => {
            if (err) {
                console.error('Ошибка при отправке сообщения:', err);
                return res.status(500).json({ error: 'Ошибка при отправке сообщения' });
            }
            db.query(
                'SELECT * FROM messages WHERE id = ?',
                [result.insertId],
                (err, rows) => {
                    if (err) return res.status(500).json({ error: 'Ошибка при получении сообщения' });
                    res.json(rows[0]);
                }
            );
        }
    );
});

// Создать чат (например, при новом заказе)
app.post('/chats', express.json(), (req, res) => {
    const { title, user_id, executor_id } = req.body;
    if (!title || !user_id || !executor_id) return res.status(400).json({ error: 'title, user_id, executor_id обязательны' });
    db.query(
        'INSERT INTO chats (title, user_id, executor_id) VALUES (?, ?, ?)',
        [title, user_id, executor_id],
        (err, result) => {
            if (err) {
                console.error('Ошибка при создании чата:', err);
                return res.status(500).json({ error: 'Ошибка при создании чата' });
            }
            db.query(
                'SELECT * FROM chats WHERE id = ?',
                [result.insertId],
                (err, rows) => {
                    if (err) return res.status(500).json({ error: 'Ошибка при получении чата' });
                    res.json(rows[0]);
                }
            );
        }
    );
});

// Получить чаты пользователя (где он заказчик или исполнитель)
app.get('/chats/user/:userId', async (req, res) => {
    try {
        const userId = req.params.userId;
        console.log('Получение чатов для пользователя:', userId);

        // Сначала получаем информацию о пользователе
        const [user] = await new Promise((resolve, reject) => {
            db.query('SELECT * FROM user WHERE id = ?', [userId], (err, results) => {
                if (err) {
                    console.error('Ошибка при получении пользователя:', err);
                    reject(err);
                } else {
                    resolve(results);
                }
            });
        });

        if (!user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }

        // Получаем чаты, где пользователь является либо заказчиком, либо исполнителем
        const query = `
            SELECT c.*, 
                   u.username as user_name,
                   e.fullname as executor_name,
                   o.project_name
            FROM chats c
            LEFT JOIN user u ON c.user_id = u.id
            LEFT JOIN executors e ON c.executor_id = e.id
            LEFT JOIN orders o ON c.id = o.chat_id
            WHERE c.user_id = ? 
               OR c.executor_id = (
                   SELECT id 
                   FROM executors 
                   WHERE user_id = ?
               )
        `;

        db.query(query, [userId, userId], async (err, results) => {
            if (err) {
                console.error('Ошибка при получении чатов:', err);
                return res.status(500).json({ error: 'Ошибка при получении чатов' });
            }
            console.log('Найдены чаты:', results);

            // --- ДОБАВЛЯЕМ unread_count ДЛЯ КАЖДОГО ЧАТА ---
            const chatIds = results.map(chat => chat.id);
            const unreadCounts = await Promise.all(chatIds.map(chatId => {
                return new Promise((resolve) => {
                    db.query(
                        `SELECT COUNT(*) as unread_count
                         FROM messages m
                         WHERE m.chat_id = ? AND m.sender_id != ? 
                         AND m.id NOT IN (
                             SELECT message_id FROM message_reads WHERE user_id = ?
                         )`,
                        [chatId, userId, userId],
                        (err, rows) => {
                            if (err) return resolve({ chatId, unread_count: 0 });
                            resolve({ chatId, unread_count: rows[0].unread_count });
                        }
                    );
                });
            }));

            const chatsWithUnread = results.map(chat => {
                const unread = unreadCounts.find(u => u.chatId === chat.id);
                return { ...chat, unread_count: unread ? unread.unread_count : 0 };
            });
            res.json(chatsWithUnread);
        });
    } catch (error) {
        console.error('Ошибка при обработке запроса чатов:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Обновление chat_id в заказе
app.put('/orders/:orderId', authenticateToken, express.json(), async (req, res) => {
    try {
        const orderId = req.params.orderId;
        const { chat_id } = req.body;

        if (!chat_id) {
            return res.status(400).json({ 
                success: false, 
                error: 'Не указан chat_id' 
            });
        }

        // Обновляем chat_id в заказе
        await new Promise((resolve, reject) => {
            db.query(
                'UPDATE orders SET chat_id = ? WHERE id = ?',
                [chat_id, orderId],
                (err, result) => {
                    if (err) {
                        console.error('Ошибка при обновлении chat_id:', err);
                        reject(err);
                    } else {
                        resolve(result);
                    }
                }
            );
        });

        res.json({ 
            success: true, 
            message: 'chat_id успешно обновлен' 
        });
    } catch (error) {
        console.error('Ошибка при обновлении chat_id:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Ошибка сервера при обновлении chat_id' 
        });
    }
});

// Создание связи между пользователем и исполнителем
app.post('/executors/link', authenticateToken, async (req, res) => {
    try {
        const { user_id, fullname } = req.body;

        if (!user_id || !fullname) {
            return res.status(400).json({
                success: false,
                error: 'Необходимо указать user_id и fullname'
            });
        }

        // Проверяем, существует ли уже связь
        const [existingExecutor] = await new Promise((resolve, reject) => {
            db.query(
                'SELECT * FROM executors WHERE user_id = ?',
                [user_id],
                (err, results) => {
                    if (err) reject(err);
                    else resolve(results);
                }
            );
        });

        if (existingExecutor) {
            return res.status(400).json({
                success: false,
                error: 'Этот пользователь уже является исполнителем'
            });
        }

        // Создаем запись исполнителя
        const result = await new Promise((resolve, reject) => {
            db.query(
                'INSERT INTO executors (user_id, fullname) VALUES (?, ?)',
                [user_id, fullname],
                (err, result) => {
                    if (err) reject(err);
                    else resolve(result);
                }
            );
        });

        res.json({
            success: true,
            message: 'Пользователь успешно назначен исполнителем',
            executor_id: result.insertId
        });
    } catch (error) {
        console.error('Ошибка при создании связи исполнителя:', error);
        res.status(500).json({
            success: false,
            error: 'Ошибка сервера при создании связи исполнителя'
        });
    }
});

// Удаление чата и всех связанных сообщений
app.delete('/chats/:chatId', async (req, res) => {
    const chatId = req.params.chatId;
    try {
        // Удаляем все сообщения этого чата
        await new Promise((resolve, reject) => {
            db.query('DELETE FROM messages WHERE chat_id = ?', [chatId], (err) => {
                if (err) return reject(err);
                resolve();
            });
        });
        // Обнуляем chat_id в заказах, связанных с этим чатом
        await new Promise((resolve, reject) => {
            db.query('UPDATE orders SET chat_id = NULL WHERE chat_id = ?', [chatId], (err) => {
                if (err) return reject(err);
                resolve();
            });
        });
        // Удаляем сам чат
        await new Promise((resolve, reject) => {
            db.query('DELETE FROM chats WHERE id = ?', [chatId], (err) => {
                if (err) return reject(err);
                resolve();
            });
        });
        res.json({ success: true, message: 'Чат и все сообщения удалены' });
    } catch (error) {
        console.error('Ошибка при удалении чата:', error);
        res.status(500).json({ success: false, error: 'Ошибка при удалении чата' });
    }
});

// --- ОТМЕТКА СООБЩЕНИЙ КАК ПРОЧИТАННЫХ ---
app.post('/chats/:chatId/read', authenticateToken, async (req, res) => {
    const chatId = req.params.chatId;
    const userId = req.user.id;

    // Получаем id всех сообщений, которые пользователь ещё не читал (и не свои)
    db.query(
        `SELECT id FROM messages 
         WHERE chat_id = ? AND sender_id != ? 
         AND id NOT IN (SELECT message_id FROM message_reads WHERE user_id = ?)`,
        [chatId, userId, userId],
        (err, rows) => {
            if (err) return res.status(500).json({ error: 'Ошибка при поиске сообщений' });
            if (!rows.length) return res.json({ success: true, updated: 0 });

            // Формируем массив для вставки
            const values = rows.map(row => [row.id, userId]);
            db.query(
                'INSERT IGNORE INTO message_reads (message_id, user_id) VALUES ?',
                [values],
                (err2, result) => {
                    if (err2) return res.status(500).json({ error: 'Ошибка при отметке сообщений как прочитанных' });
                    res.json({ success: true, updated: result.affectedRows });
                }
            );
        }
    );
});

const PORT = process.env.PORT || 3001;

app.listen(PORT, () => {
    console.log(`Сервер запущен на порту ${PORT}`);
});

// Обновляем эндпоинт для загрузки шаблона
app.post('/templates/upload', authenticateToken, upload.single('template'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({
                success: false,
                error: 'Файл не был загружен'
            });
        }

        const { service_id, name, description } = req.body;

        // Загружаем файл на MEGA
        let megaLink = '';
        try {
            megaLink = await uploadToMega(req.file.buffer, req.file.originalname);
        } catch (error) {
            console.error('Ошибка при загрузке файла на MEGA:', error);
            return res.status(500).json({
                success: false,
                error: 'Ошибка при загрузке файла на MEGA'
            });
        }

        // Сохраняем информацию о шаблоне в базе данных
        const insertQuery = `
            INSERT INTO templates (name, description, service_id, file_link, file_name)
            VALUES (?, ?, ?, ?, ?)
        `;

        db.query(insertQuery, [
            name,
            description,
            service_id,
            megaLink,
            req.file.originalname
        ], (err, result) => {
            if (err) {
                console.error('Ошибка при сохранении шаблона:', err);
                return res.status(500).json({
                    success: false,
                    error: 'Ошибка при сохранении шаблона'
                });
            }

            res.json({
                success: true,
                message: 'Шаблон успешно загружен',
                template: {
                    id: result.insertId,
                    name,
                    description,
                    service_id,
                    file_link: megaLink,
                    file_name: req.file.originalname
                }
            });
        });
    } catch (error) {
        console.error('Ошибка при загрузке шаблона:', error);
        res.status(500).json({
            success: false,
            error: 'Ошибка при загрузке шаблона'
        });
    }
});

// Обновляем эндпоинт для скачивания шаблона
app.get('/templates/:id/download', async (req, res) => {
    try {
        const templateId = req.params.id;

        // Получаем информацию о шаблоне
        const [template] = await new Promise((resolve, reject) => {
            db.query('SELECT * FROM templates WHERE id = ?', [templateId], (err, results) => {
                if (err) reject(err);
                else resolve(results);
            });
        });

        if (!template) {
            return res.status(404).json({
                success: false,
                error: 'Шаблон не найден'
            });
        }

        // Получаем файл с MEGA
        try {
            const fileBuffer = await getFromMega(template.file_link);
            res.setHeader('Content-Type', 'application/octet-stream');
            res.setHeader('Content-Disposition', `attachment; filename="${template.file_name}"`);
            res.send(fileBuffer);
        } catch (error) {
            console.error('Ошибка при скачивании файла с MEGA:', error);
            res.status(500).json({
                success: false,
                error: 'Ошибка при скачивании файла'
            });
        }
    } catch (error) {
        console.error('Ошибка при скачивании шаблона:', error);
        res.status(500).json({
            success: false,
            error: 'Ошибка при скачивании шаблона'
        });
    }
});