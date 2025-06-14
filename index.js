const http = require('http');
const fs = require('fs').promises;
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

// Настройка сессий с поддержкой HTTPS в продакшене
const sessionMiddleware = cookieSession({
    name: 'session',
    keys: [process.env.SESSION_KEY || 'my_secret_key'],
    maxAge: 24 * 60 * 60 * 1000, // 24 часа
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    httpOnly: true
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
        try {
            const connection = await mysql.createConnection(dbConfig);
            const [rows] = await connection.execute('SELECT id FROM users WHERE token = ?', [token]);
            await connection.end();
            return rows.length > 0;
        } catch (error) {
            console.error('Ошибка при проверке токена:', error);
            return false;
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
    if (!userId) throw new Error('userId is required');
    console.log(`Retrieving items for userId: ${userId}`);
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute(
        'SELECT id, text, order_index FROM items WHERE user_id = ? ORDER BY order_index',
        [userId]
    );
    await connection.end();
    return rows;
}

// Получение userId из сессии или токена
async function getUserIdFromRequest(req) {
    if (req.session && req.session.userId) return req.session.userId;
    const authHeader = req.headers['authorization'];
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        const connection = await mysql.createConnection(dbConfig);
        const [rows] = await connection.execute('SELECT id FROM users WHERE token = ?', [token]);
        await connection.end();
        if (rows.length > 0) return rows[0].id;
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
    let connection;
    try {
        connection = await mysql.createConnection(dbConfig);
        const [items] = await connection.execute(
            'SELECT id FROM items WHERE user_id = ? ORDER BY order_index',
            [userId]
        );
        for (let i = 0; i < items.length; i++) {
            await connection.execute('UPDATE items SET order_index = ? WHERE id = ?', [i + 1, items[i].id]);
        }
    } catch (error) {
        console.error('Error rebuilding order index:', error);
        throw error;
    } finally {
        if (connection) await connection.end();
    }
}

// Генерация HTML строк для пользователей (админ-панель)
async function getUserHtmlRows() {
    try {
        const connection = await mysql.createConnection(dbConfig);
        const [rows] = await connection.execute('SELECT id, login, password, role FROM users ORDER BY id');
        await connection.end();
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
        console.error('Error retrieving users:', error);
        throw error;
    }
}

// Обработчик запросов
async function handleRequest(req, res) {
    console.log('Incoming cookies:', req.headers.cookie);

    // Применяем middleware сессии
    await new Promise((resolve) => sessionMiddleware(req, res, resolve));

    console.log(`Request URL: ${req.url}, Method: ${req.method}`);

    // Обслуживание статических файлов
    if (req.url.match(/\.(html|js|css)$/)) {
        const filePath = path.join(__dirname, 'public', req.url);
        try {
            const file = await fs.readFile(filePath);
            const contentType = {
                '.html': 'text/html',
                '.js': 'application/javascript',
                '.css': 'text/css'
            }[path.extname(filePath)] || 'application/octet-stream';
            res.writeHead(200, { 'Content-Type': contentType });
            res.end(file);
        } catch (err) {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('File not found');
        }
        return;
    }

    // Маршруты API
    if (req.url === '/login' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', async () => {
            try {
                const { login, password } = JSON.parse(body);
                const connection = await mysql.createConnection(dbConfig);
                const [rows] = await connection.execute(
                    'SELECT id, role FROM users WHERE login = ? AND password = ?',
                    [login, password]
                );
                if (rows.length > 0) {
                    const token = crypto.randomBytes(32).toString('hex');
                    await connection.execute('UPDATE users SET token = ? WHERE id = ?', [token, rows[0].id]);
                    req.session.userId = rows[0].id;
                    req.session.role = rows[0].role;
                    console.log('Session after setting:', req.session);
                    await connection.end();
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true, token }));
                } else {
                    await connection.end();
                    res.writeHead(401, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'Неверный логин или пароль' }));
                }
            } catch (error) {
                console.error('Ошибка:', error);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'Ошибка сервера' }));
            }
        });
    } else if (req.url === '/' && req.method === 'GET') {
        if (isAuthenticated(req)) {
            try {
                const userRole = req.session.role || 'user';
                const adminButtonHtml = userRole === 'admin'
                    ? '<button onclick="window.location.href=\'/admin.html\'">Go to Admin Panel</button>'
                    : '';
                const html = await fs.readFile(path.join(__dirname, 'public', 'index.html'), 'utf8');
                const processedHtml = html
                    .replace('{{adminButton}}', adminButtonHtml)
                    .replace('{{userRole}}', userRole)
                    .replace('{{rows}}', await getHtmlRows(req.session.userId));
                res.writeHead(200, { 'Content-Type': 'text/html' });
                res.end(processedHtml);
            } catch (err) {
                console.error('Error in route /:', err.message);
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end('Error loading index.html: ' + err.message);
            }
        } else {
            console.log('Redirecting to /login.html');
            res.writeHead(302, { 'Location': '/login.html' });
            res.end();
        }
    } else if (req.url === '/admin.html' && req.method === 'GET') {
        if (isAuthenticated(req) && req.session.role === 'admin') {
            try {
                const html = await fs.readFile(path.join(__dirname, 'public', 'admin.html'), 'utf8');
                const processedHtml = html.replace('{{userRows}}', await getUserHtmlRows());
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
    } else if (req.method === 'POST' && req.url === '/add') {
        if (!(await isAuthenticatedOrToken(req))) {
            res.writeHead(401, { 'Content-Type': 'text/plain' });
            res.end('Unauthorized');
            return;
        }
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', async () => {
            try {
                const { text } = JSON.parse(body);
                if (!text) throw new Error('Текст не передан');
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
        req.on('data', chunk => { body += chunk; });
        req.on('end', async () => {
            try {
                const { id } = JSON.parse(body);
                if (!id) throw new Error('ID не передан');
                const userId = await getUserIdFromRequest(req);
                await deleteItem(id, userId);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true }));
            } catch (error) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: error.message }));
            }
        });
    } else if (req.method === 'POST' && req.url === '/edit') {
        if (!isAuthenticated(req)) {
            res.writeHead(401, { 'Content-Type': 'text/plain' });
            res.end('Unauthorized');
            return;
        }
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', async () => {
            try {
                const { id, text, orderIndex } = JSON.parse(body);
                if (!id || !text || orderIndex === undefined) throw new Error('ID, текст или порядок не переданы');
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
        req.on('data', chunk => { body += chunk; });
        req.on('end', async () => {
            try {
                const { id, newOrderIndex } = JSON.parse(body);
                if (!id || newOrderIndex === undefined) throw new Error('ID или новый порядок не переданы');
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
    } else {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Route not found');
    }
}

// Добавление задачи
async function addItem(text, userId) {
    const connection = await mysql.createConnection(dbConfig);
    const [result] = await connection.execute(
        'INSERT INTO items (text, user_id, order_index) VALUES (?, ?, ?)',
        [text, userId, 0]
    );
    await connection.end();
    await rebuildOrderIndex(userId);
    return result.insertId;
}

// Удаление задачи
async function deleteItem(id, userId) {
    const connection = await mysql.createConnection(dbConfig);
    const [result] = await connection.execute(
        'DELETE FROM items WHERE id = ? AND user_id = ?',
        [id, userId]
    );
    await connection.end();
    await rebuildOrderIndex(userId);
    return result;
}

// Обновление задачи
async function updateItem(id, newText, newOrderIndex, userId) {
    const connection = await mysql.createConnection(dbConfig);
    const [result] = await connection.execute(
        'UPDATE items SET text = ?, order_index = ? WHERE id = ? AND user_id = ?',
        [newText, newOrderIndex, id, userId]
    );
    await connection.end();
    await rebuildOrderIndex(userId);
    return result;
}

// Изменение порядка задач
async function reorderItem(id, newOrderIndex, userId) {
    const connection = await mysql.createConnection(dbConfig);
    const [currentItem] = await connection.execute(
        'SELECT order_index FROM items WHERE id = ? AND user_id = ?',
        [id, userId]
    );
    if (currentItem.length === 0) throw new Error('Задача не найдена');
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
    await connection.end();
    await rebuildOrderIndex(userId);
}

// Запуск сервера
const server = http.createServer(handleRequest);
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
