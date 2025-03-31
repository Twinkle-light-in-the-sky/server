// server/config/db.js
const mysql = require('mysql');

// Создаем пул подключений вместо одного подключения
const pool = mysql.createPool({
    host: 'barsikec.beget.tech',
    user: 'barsikec_er',
    password: 'Wertikal229', // Замените на ваш пароль
    database: 'barsikec_er',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    port: 3306,
    ssl: {
        rejectUnauthorized: false
    }
});

// Проверяем подключение
pool.getConnection((err, connection) => {
    if (err) {
        console.error(`Ошибка подключения к базе данных: ${err.stack}`);
        return;
    }
    console.log('Успешно подключено к базе данных MySQL.');
    connection.release();
});

module.exports = pool;

