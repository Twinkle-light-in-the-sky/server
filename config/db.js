// server/config/db.js
const mysql = require('mysql');

// Создаем пул подключений вместо одного подключения
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'barsikec.beget.tech',
    user: process.env.DB_USER || 'barsikec_er',
    password: process.env.DB_PASSWORD || 'Wertikal229',
    database: process.env.DB_NAME || 'barsikec_er',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    port: 3306,
    ssl: false
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

