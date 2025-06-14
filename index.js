const http = require('http');
const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');
const cookieSession = require('cookie-session');
const crypto = require('crypto');
const PORT = process.env.PORT || 3000;

const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
};
const pool = mysql.createPool(dbConfig);

// Настройка сессий с поддержкой HTTPS в продакшене и гибкостью для разработки
const sessionMiddleware = cookieSession({
    name: 'session',
    keys: [process.env.SESSION_KEY || 'my_secret_key'],
    maxAge: 24 * 60 * 60 * 1000, // 24 часа
    secure: process.env.NODE_ENV === 'production', // HTTPS только в продакшене
    sameSite: 'none', // Для кросс-доменных запросов
    httpOnly: true // Защита от XSS
});

// Проверка аутентификации через сессию
function isAuthenticated(req) {
    const authenticated = req.session && req.session.userId;
    console.log(`isAuthenticated: ${authenticated}`);
    return authenticated;
}

// Проверка аутентификации через сессию или токен
async function isAuthenticatedOrToken(req) {
    if (isAuthenticated(req)) return true;
    const authHeader = req.headers['authorization'];
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        const connection = await pool.getConnection();
        try {
            const [rows] = await connection.execute('SELECT id FROM users WHERE token = ?', [token]);
            return rows.length > 0;
        } catch (error) {
            console.error('Ошибка при проверке токена:', error);
            return false;
        } finally {
            connection.release();
        }
    }
    return false;
}

// Выполнение операций с повторными попытками при дедлоках
async function executeWithRetry(operation, maxRetries = 3) {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            return await operation();
        } catch (error) {
            if (error.code === 'ER_LOCK_DEADLOCK' && attempt < maxRetries) {
                console.warn(`Дедлок на попытке ${attempt}, повторяем...`);
                await new Promise(resolve => setTimeout(resolve, 100 * attempt));
                continue;
            }
            throw error;
        }
    }
}

// Получение задач пользователя
async function retrieveListItems(userId) {
    if (!userId) throw new Error('userId обязателен');
    console.log(`Получение задач для userId: ${userId}`);
    const connection = await pool.getConnection();
    try {
        const [rows] = await connection.execute(
            'SELECT id, text, order_index FROM items WHERE user_id = ? ORDER BY order_index',
            [userId]
        );
        return rows;
    } finally {
        connection.release();
    }
}

// Получение userId из сессии или токена
async function getUserIdFromRequest(req) {
    if (req.session && req.session.userId) return req.session.userId;
    const authHeader = req.headers['authorization'];
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        const connection = await pool.getConnection();
        try {
            const [rows] = await connection.execute('SELECT id FROM users WHERE token = ?', [token]);
            if (rows.length > 0) return rows[0].id;
        } finally {
            connection.release();
        }
    }
    throw new Error('Неавторизованный доступ');
}

// Генерация HTML строк для задач
async function getHtmlRows(userId) {
    const todoItems = await retrieveListItems(userId);
    return todoItems.map((item, index) => `
        <tr>
            <td>${index + 1}</td>
            <td>${item.order_index}</td>
            <td>${item.text}</td>
            <td>
                <button class="edit-btn" data-id="${item.id}">Edit</button>
                <button class="delete-btn" data-id="${item.id}">Delete</button>
                <button class="move-up-btn" data-id="${item.id}">↑</button>
                <button class="move-down-btn" data-id="${item.id}">↓</button>
            </td>
        </tr>
    `).join('');
}

// Перестройка order_index
async function rebuildOrderIndex(userId) {
    const connection = await pool.getConnection();
    try {
        const [items] = await connection.execute(
            'SELECT id FROM items WHERE user_id = ? ORDER BY order_index',
            [userId]
        );
        for (let i = 0; i < items.length; i++) {
            await connection.execute('UPDATE items SET order_index = ? WHERE id = ?', [i + 1, items[i].id]);
        }
    } catch (error) {
        console.error('Ошибка перестройки порядка:', error);
        throw error;
    } finally {
        connection.release();
    }
}

// Генерация HTML строк для пользователей (админ-панель)
async function getUserHtmlRows() {
    const connection = await pool.getConnection();
    try {
        const [rows] = await connection.execute('SELECT id, login, password, role FROM users ORDER BY id');
        return rows.map(user => `
            <tr>
                <td>${user.id}</td>
                <td>${user.login}</td>
                <td class="password-cell">
                    <input type="password" value="${user.password}" disabled>
                    <button class="show-password-btn">👁️</button>
                </td>
                <td>${user.role === 'admin' ? 'Да' : 'Нет'}</td>
                <td>
                    <button class="edit-btn" data-id="${user.id}">Edit</button>
                    <button class="delete-btn" data-id="${user.id}">Delete</button>
                </td>
            </tr>
        `).join('');
    } catch (error) {
        console.error('Ошибка получения пользователей:', error);
        throw error;
    } finally {
        connection.release();
    }
}

// Обработчик запросов
async function handleRequest(req, res) {
    console.log('Входящие cookies:', req.headers.cookie);
    sessionMiddleware(req, res, () => {}); // Применяем middleware сессий

    if (req.url === '/login' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', async () => {
            let connection;
            try {
                const { login, password } = JSON.parse(body);
                connection = await pool.getConnection();
                const [rows] = await connection.execute(
                    'SELECT id, role FROM users WHERE login = ? AND password = ?',
                    [login, password]
                );
                if (rows.length > 0) {
                    const token = crypto.randomBytes(32).toString('hex');
                    await connection.execute('UPDATE users SET token = ? WHERE id = ?', [token, rows[0].id]);
                    req.session.userId = rows[0].id;
                    req.session.role = rows[0].role;
                    console.log('Сессия после установки:', req.session);
                    res.setHeader('Content-Type', 'application/json');
                    res.statusCode = 200;
                    res.end(JSON.stringify({ success: true, token }));
                } else {
                    res.statusCode = 401;
                    res.setHeader('Content-Type', 'application/json');
                    res.end(JSON.stringify({ success: false, error: 'Неверный логин или пароль' }));
                }
            } catch (error) {
                console.error('Ошибка:', error);
                res.statusCode = 500;
                res.setHeader('Content-Type', 'application/json');
                res.end(JSON.stringify({ success: false, error: 'Ошибка сервера' }));
            } finally {
                if (connection) connection.release();
                console.log('Set-Cookie header:', res.getHeader('Set-Cookie'));
            }
        });
    } else if (req.url === '/' && req.method === 'GET') {
        if (isAuthenticated(req)) {
            try {
                const userRole = req.session.role || 'user';
                const adminButtonHtml = userRole === 'admin' ? '<button onclick="window.location.href=\'/admin.html\'">Go to Admin Panel</button>' : '';
                const html = await fs.promises.readFile(path.join(__dirname, 'index.html'), 'utf8');
                const processedHtml = html.replace('{{adminButton}}', adminButtonHtml)
                    .replace('{{userRole}}', userRole)
                    .replace('{{rows}}', await getHtmlRows(req.session.userId));
                res.statusCode = 200;
                res.setHeader('Content-Type', 'text/html');
                res.end(processedHtml);
            } catch (err) {
                console.error('Ошибка в маршруте /:', err.message);
                res.statusCode = 500;
                res.setHeader('Content-Type', 'text/plain');
                res.end('Ошибка загрузки index.html: ' + err.message);
            }
        } else {
            console.log('Перенаправление на /login');
            res.statusCode = 302;
            res.setHeader('Location', '/login');
            res.end();
        }
    } else if (req.url === '/admin.html' && req.method === 'GET') {
        if (isAuthenticated(req) && req.session.role === 'admin') {
            try {
                const html = await fs.promises.readFile(path.join(__dirname, 'admin.html'), 'utf8');
                const userRows = await getUserHtmlRows();
                const processedHtml = html.replace('{{userRows}}', userRows);
                res.writeHead(200, { 'Content-Type': 'text/html' });
                res.end(processedHtml);
            } catch (err) {
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end('Ошибка загрузки admin.html');
            }
        } else {
            res.writeHead(403, { 'Content-Type': 'text/plain' });
            res.end('Доступ запрещен');
        }
    } else if (req.method === 'POST' && req.url === '/addUser') {
        if (!isAuthenticated(req) || req.session.role !== 'admin') {
            res.writeHead(403, { 'Content-Type': 'text/plain' });
            res.end('Доступ запрещен');
            return;
        }
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', async () => {
            try {
                const { login, password, isAdmin } = JSON.parse(body);
                if (!login || !password) throw new Error('Логин и пароль обязательны');
                const role = isAdmin === 'on' ? 'admin' : 'user';
                const is_admin = role === 'admin' ? 1 : 0;
                const connection = await pool.getConnection();
                try {
                    await connection.execute(
                        'INSERT INTO users (login, password, is_admin, role) VALUES (?, ?, ?, ?)',
                        [login, password, is_admin, role]
                    );
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true }));
                } finally {
                    connection.release();
                }
            } catch (error) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: error.message }));
            }
        });
    } else if (req.method === 'POST' && req.url === '/deleteUser') {
        if (!isAuthenticated(req) || req.session.role !== 'admin') {
            res.writeHead(403, { 'Content-Type': 'text/plain' });
            res.end('Доступ запрещен');
            return;
        }
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', async () => {
            try {
                const { id } = JSON.parse(body);
                if (!id) throw new Error('ID пользователя обязателен');
                const connection = await pool.getConnection();
                try {
                    await connection.execute('DELETE FROM users WHERE id = ?', [id]);
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true }));
                } finally {
                    connection.release();
                }
            } catch (error) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: error.message }));
            }
        });
    } else if (req.method === 'POST' && req.url === '/editUser') {
        if (!isAuthenticated(req) || req.session.role !== 'admin') {
            res.writeHead(403, { 'Content-Type': 'text/plain' });
            res.end('Доступ запрещен');
            return;
        }
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', async () => {
            try {
                const { id, login, password, isAdmin } = JSON.parse(body);
                if (!id || !login || !password) throw new Error('ID, логин и пароль обязательны');
                const role = isAdmin === 'on' ? 'admin' : 'user';
                const is_admin = role === 'admin' ? 1 : 0;
                const connection = await pool.getConnection();
                try {
                    await connection.execute(
                        'UPDATE users SET login = ?, password = ?, is_admin = ?, role = ? WHERE id = ?',
                        [login, password, is_admin, role, id]
                    );
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true }));
                } finally {
                    connection.release();
                }
            } catch (error) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: error.message }));
            }
        });
    } else if (req.method === 'POST' && req.url === '/getPassword') {
        if (!isAuthenticated(req) || req.session.role !== 'admin') {
            res.writeHead(403, { 'Content-Type': 'text/plain' });
            res.end('Доступ запрещен');
            return;
        }
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', async () => {
            try {
                const { id } = JSON.parse(body);
                if (!id) throw new Error('ID пользователя обязателен');
                const connection = await pool.getConnection();
                try {
                    const [rows] = await connection.execute('SELECT password FROM users WHERE id = ?', [id]);
                    if (rows.length > 0) {
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: true, password: rows[0].password }));
                    } else {
                        res.writeHead(404, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: false, error: 'Пользователь не найден' }));
                    }
                } finally {
                    connection.release();
                }
            } catch (error) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: error.message }));
            }
        });
    } else if (req.method === 'POST' && req.url === '/add') {
        if (!(await isAuthenticatedOrToken(req))) {
            res.writeHead(401, { 'Content-Type': 'text/plain' });
            res.end('Unauthorized');
            return;
        }
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', async () => {
            try {
                const { text } = JSON.parse(body);
                if (!text) throw new Error('Текст обязателен');
                const userId = await getUserIdFromRequest(req);
                const newItemId = await addItem(text, userId);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true, id: newItemId }));
            } catch (error) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: error.message }));
            }
        });
    } else if (req.method === 'POST' && req.url === '/delete') {
        if (!(await isAuthenticatedOrToken(req))) {
            res.writeHead(401, { 'Content-Type': 'text/plain' });
            res.end('Unauthorized');
            return;
        }
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', async () => {
            try {
                const { id } = JSON.parse(body);
                if (!id) throw new Error('ID обязателен');
                const userId = await getUserIdFromRequest(req);
                await deleteItem(id, userId);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true }));
            } catch (error) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: error.message }));
            }
        });
    } else if (req.url.startsWith('/getItem') && req.method === 'GET') {
        if (!isAuthenticated(req)) {
            res.writeHead(401, { 'Content-Type': 'text/plain' });
            res.end('Unauthorized');
            return;
        }
        const queryString = req.url.split('?')[1];
        if (!queryString) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Отсутствуют параметры запроса' }));
            return;
        }
        const urlParams = new URLSearchParams(queryString);
        const id = urlParams.get('id');
        if (!id) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'ID обязателен' }));
            return;
        }
        try {
            const userId = req.session.userId;
            const connection = await pool.getConnection();
            try {
                const [rows] = await connection.execute(
                    'SELECT text, order_index FROM items WHERE id = ? AND user_id = ?',
                    [id, userId]
                );
                if (rows.length > 0) {
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true, item: rows[0] }));
                } else {
                    res.writeHead(404, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'Задача не найдена' }));
                }
            } finally {
                connection.release();
            }
        } catch (error) {
            console.error('Ошибка:', error);
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Ошибка сервера' }));
        }
    } else if (req.method === 'POST' && req.url === '/edit') {
        if (!isAuthenticated(req)) {
            res.writeHead(401, { 'Content-Type': 'text/plain' });
            res.end('Unauthorized');
            return;
        }
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', async () => {
            try {
                const { id, text, orderIndex } = JSON.parse(body);
                if (!id || !text || orderIndex === undefined) throw new Error('ID, текст или порядок обязательны');
                const userId = await getUserIdFromRequest(req);
                await updateItem(id, text, orderIndex, userId);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true }));
            } catch (error) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: error.message }));
            }
        });
    } else if (req.method === 'POST' && req.url === '/reorder') {
        if (!(await isAuthenticatedOrToken(req))) {
            res.writeHead(401, { 'Content-Type': 'text/plain' });
            res.end('Unauthorized');
            return;
        }
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', async () => {
            try {
                const { id, newOrderIndex } = JSON.parse(body);
                if (!id || newOrderIndex === undefined) throw new Error('ID или новый порядок обязательны');
                const userId = await getUserIdFromRequest(req);
                await reorderItem(id, newOrderIndex, userId);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true }));
            } catch (error) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: error.message }));
            }
        });
    } else if (req.method === 'POST' && req.url === '/logout') {
        req.session = null;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
    } else if (req.url === '/api/items' && req.method === 'GET') {
        const authHeader = req.headers['authorization'];
        if (authHeader && authHeader.startsWith('Bearer ')) {
            const token = authHeader.substring(7);
            const connection = await pool.getConnection();
            try {
                const [rows] = await connection.execute('SELECT id FROM users WHERE token = ?', [token]);
                if (rows.length > 0) {
                    const userId = rows[0].id;
                    const items = await retrieveListItems(userId);
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify(items));
                } else {
                    res.writeHead(401, { 'Content-Type': 'text/plain' });
                    res.end('Unauthorized');
                }
            } catch (error) {
                console.error('Ошибка:', error);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'Ошибка получения задач' }));
            } finally {
                connection.release();
            }
        } else {
            res.writeHead(401, { 'Content-Type': 'text/plain' });
            res.end('Unauthorized');
        }
    } else if (req.method === 'POST' && req.url === '/moveUp') {
        if (!(await isAuthenticatedOrToken(req))) {
            res.writeHead(401, { 'Content-Type': 'text/plain' });
            res.end('Unauthorized');
            return;
        }
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', async () => {
            try {
                const { id } = JSON.parse(body);
                if (!id) throw new Error('ID обязателен');
                const userId = await getUserIdFromRequest(req);
                await moveUp(id, userId);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true }));
            } catch (error) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: error.message }));
            }
        });
    } else if (req.method === 'POST' && req.url === '/moveDown') {
        if (!(await isAuthenticatedOrToken(req))) {
            res.writeHead(401, { 'Content-Type': 'text/plain' });
            res.end('Unauthorized');
            return;
        }
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', async () => {
            try {
                const { id } = JSON.parse(body);
                if (!id) throw new Error('ID обязателен');
                const userId = await getUserIdFromRequest(req);
                await moveDown(id, userId);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true }));
            } catch (error) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: error.message }));
            }
        });
    } else {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Маршрут не найден');
    }
}

// Добавление задачи
async function addItem(text, userId) {
    const connection = await pool.getConnection();
    try {
        const [maxOrder] = await connection.execute(
            'SELECT MAX(order_index) as max FROM items WHERE user_id = ?',
            [userId]
        );
        const newOrderIndex = (maxOrder[0].max || 0) + 1;
        const [result] = await connection.execute(
            'INSERT INTO items (text, user_id, order_index) VALUES (?, ?, ?)',
            [text, userId, newOrderIndex]
        );
        return result.insertId;
    } catch (error) {
        console.error('Ошибка добавления задачи:', error);
        throw error;
    } finally {
        connection.release();
    }
}

// Изменение порядка задач
async function reorderItem(id, newOrderIndex, userId) {
    const connection = await pool.getConnection();
    try {
        await connection.beginTransaction();
        const [currentItem] = await connection.execute(
            'SELECT order_index FROM items WHERE id = ? AND user_id = ? FOR UPDATE',
            [id, userId]
        );
        if (!currentItem.length) throw new Error('Задача не найдена');
        const currentOrderIndex = currentItem[0].order_index;
        if (newOrderIndex > currentOrderIndex) {
            await connection.execute(
                'UPDATE items SET order_index = order_index - 1 WHERE user_id = ? AND order_index > ? AND order_index <= ?',
                [userId, currentOrderIndex, newOrderIndex]
            );
        } else if (newOrderIndex < currentOrderIndex) {
            await connection.execute(
                'UPDATE items SET order_index = order_index + 1 WHERE user_id = ? AND order_index >= ? AND order_index < ?',
                [userId, newOrderIndex, currentOrderIndex]
            );
        }
        await connection.execute(
            'UPDATE items SET order_index = ? WHERE id = ? AND user_id = ?',
            [newOrderIndex, id, userId]
        );
        await connection.commit();
    } catch (error) {
        await connection.rollback();
        console.error('Ошибка изменения порядка:', error);
        throw error;
    } finally {
        connection.release();
    }
}

// Удаление задачи
async function deleteItem(id, userId) {
    const connection = await pool.getConnection();
    try {
        await connection.execute('DELETE FROM items WHERE id = ? AND user_id = ?', [id, userId]);
        await rebuildOrderIndex(userId);
    } catch (error) {
        console.error('Ошибка удаления задачи:', error);
        throw error;
    } finally {
        connection.release();
    }
}

// Обновление задачи
async function updateItem(id, newText, newOrderIndex, userId) {
    const connection = await pool.getConnection();
    try {
        await connection.execute(
            'UPDATE items SET text = ?, order_index = ? WHERE id = ? AND user_id = ?',
            [newText, newOrderIndex, id, userId]
        );
        await rebuildOrderIndex(userId);
    } catch (error) {
        console.error('Ошибка обновления задачи:', error);
        throw error;
    } finally {
        connection.release();
    }
}

// Перемещение задачи вверх
const moveUp = async (id, userId) => {
    await executeWithRetry(async () => {
        const connection = await pool.getConnection();
        try {
            await connection.beginTransaction();
            const [itemRows] = await connection.execute(
                'SELECT order_index FROM items WHERE id = ? AND user_id = ? FOR UPDATE',
                [id, userId]
            );
            if (!itemRows.length) throw new Error('Задача не найдена');
            const currentOrderIndex = itemRows[0].order_index;
            const [aboveRows] = await connection.execute(
                'SELECT id, order_index FROM items WHERE user_id = ? AND order_index < ? ORDER BY order_index DESC LIMIT 1 FOR UPDATE',
                [userId, currentOrderIndex]
            );
            if (!aboveRows.length) throw new Error('Нет задачи выше для обмена');
            const aboveItem = aboveRows[0];
            await connection.execute('UPDATE items SET order_index = ? WHERE id = ?', [aboveItem.order_index, id]);
            await connection.execute('UPDATE items SET order_index = ? WHERE id = ?', [currentOrderIndex, aboveItem.id]);
            await connection.commit();
        } catch (error) {
            await connection.rollback();
            throw error;
        } finally {
            connection.release();
        }
    });
};

// Перемещение задачи вниз
const moveDown = async (id, userId) => {
    await executeWithRetry(async () => {
        const connection = await pool.getConnection();
        try {
            await connection.beginTransaction();
            const [itemRows] = await connection.execute(
                'SELECT order_index FROM items WHERE id = ? AND user_id = ? FOR UPDATE',
                [id, userId]
            );
            if (!itemRows.length) throw new Error('Задача не найдена');
            const currentOrderIndex = itemRows[0].order_index;
            const [belowRows] = await connection.execute(
                'SELECT id, order_index FROM items WHERE user_id = ? AND order_index > ? ORDER BY order_index ASC LIMIT 1 FOR UPDATE',
                [userId, currentOrderIndex]
            );
            if (!belowRows.length) throw new Error('Нет задачи ниже для обмена');
            const belowItem = belowRows[0];
            await connection.execute('UPDATE items SET order_index = ? WHERE id = ?', [belowItem.order_index, id]);
            await connection.execute('UPDATE items SET order_index = ? WHERE id = ?', [currentOrderIndex, belowItem.id]);
            await connection.commit();
        } catch (error) {
            await connection.rollback();
            throw error;
        } finally {
            connection.release();
        }
    });
};

// Запуск сервера
const server = http.createServer(handleRequest);
server.listen(PORT, () => console.log(`Сервер запущен на порту ${PORT}`));
