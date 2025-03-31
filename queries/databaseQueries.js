const db = require('../config/db');

// Пример функции для получения всех исполнителей
const getAllExecutors = () => {
    return new Promise((resolve, reject) => {
        db.query('SELECT id, fullname, phone, email FROM executors', (err, results) => {
            if (err) {
                return reject(err);
            }
            resolve(results);
        });
    });
};

const getActiveOrders = () => {
    return new Promise((resolve, reject) => {
        db.query('SELECT * FROM orders WHERE status_id IN (1, 2, 3, 4)', (err, results) => {
            if (err) {
                return reject(err);
            }
            resolve(results);
        });
    });
};

// Функция для получения завершенных заказов
const getCompletedOrders = () => {
    return new Promise((resolve, reject) => {
        // Получаем только завершенные заказы
        db.query('SELECT * FROM orders WHERE status_id IN (5, 6)', (err, results) => {
            if (err) {
                return reject(err);
            }
            resolve(results);
        });
    });
};

// Экспортируйте функции
module.exports = {
    getAllExecutors,
    getActiveOrders,
    getCompletedOrders,
};
