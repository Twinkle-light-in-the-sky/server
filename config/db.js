// server/config/db.js
const mysql = require('mysql');

// Создаем подключение к базе данных
const connection = mysql.createConnection({
    host: process.env.DB_HOST || '127.0.0.1', // Обычно localhost для OpenServer
    user: process.env.DB_USER || 'root',      // Имя пользователя (по умолчанию root)
    password: process.env.DB_PASSWORD || '',   // Пароль (по умолчанию пустой)
    database: process.env.DB_NAME || 'Startset', // Имя вашей базы данных
});

// Подключаемся к базе данных
connection.connect((err) => {
    if (err) {
        console.error(`Ошибка подключения к базе данных: ${err.stack}`);
        return;
    }
    console.log('Успешно подключено к базе данных MySQL.');
});

// Экспортируем подключение для использования в других файлах
module.exports = connection;

