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

const session = cookieSession({
    name: 'session',
    keys: ['my_secret_key'],
    maxAge: 24 * 60 * 60 * 1000,
    secure: process.env.NODE_ENV === 'production', // Включает secure в продакшене
    sameSite: 'lax' // Защита от CSRF
});
function isAuthenticated(req) {
    return req.session && req.session.userId;
}

async function isAuthenticatedOrToken(req) {
    if (req.session && req.session.userId) {
        return true;
    }
    const authHeader = req.headers['authorization'];
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        try {
            const connection = await mysql.createConnection(dbConfig);
            const [rows] = await connection.execute(
                'SELECT id FROM users WHERE token = ?',
                [token]
            );
            await connection.end();
            return rows.length > 0;
        } catch (error) {
            console.error('Ошибка при проверке токена:', error);
            return false;
        }
    }
    return false;
}

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

async function retrieveListItems(userId) {
    try {
        const connection = await mysql.createConnection(dbConfig);
        const query = 'SELECT id, text, order_index FROM items WHERE user_id = ? ORDER BY order_index';
        const [rows] = await connection.execute(query, [userId]);
            console.log(`Items for user ${userId}:`, rows.map(item => ({id: item.id, order_index: item.order_index})));
        await connection.end();
        return rows;
    } catch (error) {
        console.error('Error retrieving list items:', error);
        throw error;
    }
}

async function getUserIdFromRequest(req) {
    if (req.session && req.session.userId) {
        return req.session.userId;
    }
    const authHeader = req.headers['authorization'];
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        const connection = await mysql.createConnection(dbConfig);
        const [rows] = await connection.execute(
            'SELECT id FROM users WHERE token = ?',
            [token]
        );
        await connection.end();
        if (rows.length > 0) {
            return rows[0].id;
        }
    }
    throw new Error('Неавторизованный доступ');
}

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

async function rebuildOrderIndex(userId) {
    let connection;
    try {
        connection = await mysql.createConnection(dbConfig);
        const [items] = await connection.execute(
            'SELECT id FROM items WHERE user_id = ? ORDER BY order_index',
            [userId]
        );
        for (let i = 0; i < items.length; i++) {
            await connection.execute(
                'UPDATE items SET order_index = ? WHERE id = ?',
                [i + 1, items[i].id]
            );
        }
    } catch (error) {
        console.error('Error rebuilding order index:', error);
        throw error;
    } finally {
        if (connection) await connection.end();
    }
}

async function handleRequest(req, res) {
    session(req, res, async () => {
        if (req.url === '/login' && req.method === 'GET') {
            try {
                const html = await fs.promises.readFile(path.join(__dirname, 'login.html'), 'utf8');
                console.log(`Logged in user: ${login}, id: ${rows[0].id}, role: ${rows[0].role}`);
                res.writeHead(200, { 'Content-Type': 'text/html' });
                res.end(html);
            } catch (err) {
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end('Error loading login.html');
            }
        } else if (req.url === '/login' && req.method === 'POST') {
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
                        await connection.execute(
                            'UPDATE users SET token = ? WHERE id = ?',
                            [token, rows[0].id]
                        );
                        req.session.userId = rows[0].id;
                        req.session.role = rows[0].role;
                        await connection.end();
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: true, token: token }));
                    } else {
                        await connection.end();
                        res.writeHead(401, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: false, error: 'Неверный логин или пароль' }));
                    }
                } catch (error) {
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'Ошибка сервера' }));
                }
            });
        } else if (req.url === '/' && req.method === 'GET') {
            if (!req.session) {
                console.error('Session not initialized');
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end('Session error');
                return;
            }
            if (isAuthenticated(req)) {
                try {
                    const userRole = req.session.role || 'user';
                    let adminButtonHtml = '';
                    if (userRole === 'admin') {
                        adminButtonHtml = '<button onclick="window.location.href=\'/admin.html\'">Go to Admin Panel</button>';
                    }
                    const html = await fs.promises.readFile(path.join(__dirname, 'index.html'), 'utf8');
                    if (!html) {
                        throw new Error('HTML content is empty');
                    }
                    const processedHtml = html.replace('{{adminButton}}', adminButtonHtml || '')
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
                res.writeHead(302, { 'Location': '/login' });
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
            req.on('data', chunk => { body += chunk; });
            req.on('end', async () => {
                try {
                    const { login, password, isAdmin } = JSON.parse(body);
                    if (!login || !password) {
                        throw new Error('Логин и пароль обязательны');
                    }
                    const role = isAdmin === 'on' ? 'admin' : 'user';
                    const is_admin = role === 'admin' ? 1 : 0;
                    const connection = await mysql.createConnection(dbConfig);
                    await connection.execute(
                        'INSERT INTO users (login, password, is_admin, role) VALUES (?, ?, ?, ?)',
                        [login, password, is_admin, role]
                    );
                    await connection.end();
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true }));
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
            req.on('data', chunk => { body += chunk; });
            req.on('end', async () => {
                try {
                    const { id } = JSON.parse(body);
                    if (!id) throw new Error('ID пользователя обязателен');
                    const connection = await mysql.createConnection(dbConfig);
                    await connection.execute('DELETE FROM users WHERE id = ?', [id]);
                    await connection.end();
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true }));
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
            req.on('data', chunk => { body += chunk; });
            req.on('end', async () => {
                try {
                    const { id, login, password, isAdmin } = JSON.parse(body);
                    if (!id || !login || !password) {
                        throw new Error('ID, логин и пароль обязательны');
                    }
                    const role = isAdmin === 'on' ? 'admin' : 'user';
                    const is_admin = role === 'admin' ? 1 : 0;
                    const connection = await mysql.createConnection(dbConfig);
                    await connection.execute(
                        'UPDATE users SET login = ?, password = ?, is_admin = ?, role = ? WHERE id = ?',
                        [login, password, is_admin, role, id]
                    );
                    await connection.end();
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true }));
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
            req.on('data', chunk => { body += chunk; });
            req.on('end', async () => {
                try {
                    const { id } = JSON.parse(body);
                    if (!id) throw new Error('ID пользователя обязателен');
                    const connection = await mysql.createConnection(dbConfig);
                    const [rows] = await connection.execute('SELECT password FROM users WHERE id = ?', [id]);
                    await connection.end();
                    if (rows.length > 0) {
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: true, password: rows[0].password }));
                    } else {
                        res.writeHead(404, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: false, error: 'Пользователь не найден' }));
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
            req.on('data', chunk => { body += chunk; });
            req.on('end', async () => {
                try {
                    const { text } = JSON.parse(body);
                    if (!text) throw new Error("Текст не передан");
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
                    if (!id) throw new Error("ID не передан");
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
            const urlParams = new URLSearchParams(req.url.split('?')[1]);
            const id = urlParams.get('id');
            try {
                const userId = req.session.userId;
                const connection = await mysql.createConnection(dbConfig);
                const [rows] = await connection.execute(
                    'SELECT text, order_index FROM items WHERE id = ? AND user_id = ?',
                    [id, userId]
                );
                await connection.end();
                if (rows.length > 0) {
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true, item: rows[0] }));
                } else {
                    res.writeHead(404, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'Задача не найдена' }));
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
            req.on('data', chunk => { body += chunk; });
            req.on('end', async () => {
                try {
                    const { id, text, orderIndex } = JSON.parse(body);
                    if (!id || !text || orderIndex === undefined) throw new Error("ID, текст или порядок не переданы");
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
                    if (!id || newOrderIndex === undefined) throw new Error("ID или новый порядок не переданы");
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
                try {
                    const connection = await mysql.createConnection(dbConfig);
                    const [rows] = await connection.execute(
                        'SELECT id FROM users WHERE token = ?',
                        [token]
                    );
                    if (rows.length > 0) {
                        const userId = rows[0].id;
                        const items = await retrieveListItems(userId);
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify(items));
                    } else {
                        res.writeHead(401, { 'Content-Type': 'text/plain' });
                        res.end('Unauthorized');
                    }
                    await connection.end();
                } catch (error) {
                    console.error('Ошибка:', error);
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'Error retrieving items' }));
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
            req.on('data', chunk => { body += chunk; });
            req.on('end', async () => {
                try {
                    const { id } = JSON.parse(body);
                    if (!id) throw new Error("ID не передан");
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
            req.on('data', chunk => { body += chunk; });
            req.on('end', async () => {
                try {
                    const { id } = JSON.parse(body);
                    if (!id) throw new Error("ID не передан");
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
            res.end('Route not found');
        }
    });
}

async function addItem(text, userId) {
    try {
        const connection = await mysql.createConnection(dbConfig);
        const query = 'INSERT INTO items (text, user_id, order_index) VALUES (?, ?, ?)';
        const [result] = await connection.execute(query, [text, userId, 0]);
        await connection.end();
        await rebuildOrderIndex(userId);
        return result.insertId;
    } catch (error) {
        console.error('Error adding item:', error);
        throw error;
    }
}

async function reorderItem(id, newOrderIndex, userId) {
    try {
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
    } catch (error) {
        console.error('Error reordering item:', error);
        throw error;
    }
}

async function deleteItem(id, userId) {
    try {
        const connection = await mysql.createConnection(dbConfig);
        const query = 'DELETE FROM items WHERE id = ? AND user_id = ?';
        const [result] = await connection.execute(query, [id, userId]);
        await connection.end();
        await rebuildOrderIndex(userId);
        return result;
    } catch (error) {
        console.error('Error deleting item:', error);
        throw error;
    }
}

async function updateItem(id, newText, newOrderIndex, userId) {
    try {
        const connection = await mysql.createConnection(dbConfig);
        const query = 'UPDATE items SET text = ?, order_index = ? WHERE id = ? AND user_id = ?';
        const [result] = await connection.execute(query, [newText, newOrderIndex, id, userId]);
        await connection.end();
        await rebuildOrderIndex(userId);
        return result;
    } catch (error) {
        console.error('Error updating item:', error);
        throw error;
    }
}

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

const moveUp = async (id, userId) => {
  await executeWithRetry(async () => {
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();

      const [itemRows] = await connection.execute(
        'SELECT order_index FROM items WHERE id = ? AND user_id = ? FOR UPDATE',
        [id, userId]
      );
      if (!itemRows.length) throw new Error('Item not found');
      const currentOrderIndex = itemRows[0].order_index;

      const [aboveRows] = await connection.execute(
        'SELECT id, order_index FROM items WHERE user_id = ? AND order_index < ? ORDER BY order_index DESC LIMIT 1 FOR UPDATE',
        [userId, currentOrderIndex]
      );
      if (!aboveRows.length) throw new Error('No item above to swap with');
      const aboveItem = aboveRows[0];

      // Fix the "move up" logic by ensuring only the direct neighbor is swapped
      await connection.execute(
        'UPDATE items SET order_index = ? WHERE id = ?',
        [aboveItem.order_index, id]
      );
      await connection.execute(
        'UPDATE items SET order_index = ? WHERE id = ?',
        [currentOrderIndex, aboveItem.id]
      );

      await connection.commit();
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  });
};


const moveDown = async (id, userId) => {
  await executeWithRetry(async () => {
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();

      const [itemRows] = await connection.execute(
        'SELECT order_index FROM items WHERE id = ? AND user_id = ? FOR UPDATE',
        [id, userId]
      );
      if (!itemRows.length) throw new Error('Item not found');
      const currentOrderIndex = itemRows[0].order_index;

      const [belowRows] = await connection.execute(
        'SELECT id, order_index FROM items WHERE user_id = ? AND order_index > ? ORDER BY order_index ASC LIMIT 1 FOR UPDATE',
        [userId, currentOrderIndex]
      );
      if (!belowRows.length) throw new Error('No item below to swap with');
      const belowItem = belowRows[0];

      await connection.execute(
        'UPDATE items SET order_index = ? WHERE id = ?',
        [belowItem.order_index, id]
      );
      await connection.execute(
        'UPDATE items SET order_index = ? WHERE id = ?',
        [currentOrderIndex, belowItem.id]
      );

      await connection.commit();
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  });
};

const server = http.createServer(handleRequest);
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
