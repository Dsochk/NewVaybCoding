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

// Настройка сессий с поддержкой HTTPS в продакшене
const session = cookieSession({
    name: 'session',
    keys: [process.env.SESSION_KEY || 'my_secret_key'],
    maxAge: 24 * 60 * 60 * 1000, // 24 часа
    secure: process.env.NODE_ENV === 'production', // Secure для HTTPS
    sameSite: 'lax', // Защита от CSRF
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
    if (isAuthenticated(req)) {
        return true;
    }
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
    if (!userId) {
        throw new Error('userId is required');
    }
    console.log(`Retrieving items for userId: ${userId}`);
    const connection = await mysql.createConnection(dbConfig);
    const query = 'SELECT id, text, order_index FROM items WHERE user_id = ? ORDER BY order_index';
    const [rows] = await connection.execute(query, [userId]);
    await connection.end();
    return rows;
}

// Получение userId из сессии или токена
async function getUserIdFromRequest(req) {
    if (req.session && req.session.userId) {
        return req.session.userId;
    }
    const authHeader = req.headers['authorization'];
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        const connection = await mysql.createConnection(dbConfig);
        const [rows] = await connection.execute('SELECT id FROM users WHERE token = ?', [token]);
        await connection.end();
        if (rows.length > 0) {
            return rows[0].id;
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
    let connection;
    try {
        connection = await mysql.createConnection(dbConfig);
        const [items] = await connection.execute('SELECT id FROM items WHERE user_id = ? ORDER BY order_index', [userId]);
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

// Обработчик запросов
async function handleRequest(req, res) {
    console.log('Incoming cookies:', req.headers.cookie);
    session(req, res, (err) => {
        if (err) {
            console.error('Session error:', err);
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end('Session error');
            return;
        }
        console.log(`Request URL: ${req.url}, Method: ${req.method}`);

        if (req.url === '/login' && req.method === 'GET') {
            fs.promises.readFile(path.join(__dirname, 'login.html'), 'utf8')
                .then(html => {
                    res.writeHead(200, { 'Content-Type': 'text/html' });
                    res.end(html);
                })
                .catch(err => {
                    res.writeHead(500, { 'Content-Type': 'text/plain' });
                    res.end('Error loading login.html');
                });
        } else if (req.url === '/login' && req.method === 'POST') {
            let body = '';
            req.on('data', chunk => { body += chunk; });
            req.on('end', () => {
                try {
                    const { login, password } = JSON.parse(body);
                    mysql.createConnection(dbConfig).then(connection => {
                        connection.execute('SELECT id, role FROM users WHERE login = ? AND password = ?', [login, password])
                            .then(([rows]) => {
                                if (rows.length > 0) {
                                    const token = crypto.randomBytes(32).toString('hex');
                                    connection.execute('UPDATE users SET token = ? WHERE id = ?', [token, rows[0].id])
                                        .then(() => {
                                            console.log(`Logged in user: ${login}, id: ${rows[0].id}, role: ${rows[0].role}`);
                                            console.log('Session before setting:', req.session);
                                            req.session.userId = rows[0].id;
                                            req.session.role = rows[0].role;
                                            console.log('Session after setting:', req.session);
                                            connection.end();
                                            res.writeHead(200, { 'Content-Type': 'application/json' });
                                            res.end(JSON.stringify({ success: true, token: token }));
                                        })
                                        .catch(err => {
                                            connection.end();
                                            throw err;
                                        });
                                } else {
                                    connection.end();
                                    res.writeHead(401, { 'Content-Type': 'application/json' });
                                    res.end(JSON.stringify({ success: false, error: 'Неверный логин или пароль' }));
                                }
                            })
                            .catch(error => {
                                connection.end();
                                console.error('Ошибка:', error);
                                res.writeHead(500, { 'Content-Type': 'application/json' });
                                res.end(JSON.stringify({ success: false, error: 'Ошибка сервера' }));
                            });
                    }).catch(error => {
                        console.error('Ошибка подключения к БД:', error);
                        res.writeHead(500, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: false, error: 'Ошибка сервера' }));
                    });
                } catch (error) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'Некорректный запрос' }));
                }
            });
        } else if (req.url === '/' && req.method === 'GET') {
            console.log('Checking session for /');
            if (!req.session) {
                console.error('Session not initialized');
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end('Session error');
                return;
            }
            if (isAuthenticated(req)) {
                const userRole = req.session.role || 'user';
                let adminButtonHtml = '';
                if (userRole === 'admin') {
                    adminButtonHtml = '<button onclick="window.location.href=\'/admin.html\'">Go to Admin Panel</button>';
                }
                fs.promises.readFile(path.join(__dirname, 'index.html'), 'utf8')
                    .then(html => {
                        if (!html) throw new Error('HTML content is empty');
                        return getHtmlRows(req.session.userId).then(rows => {
                            const processedHtml = html.replace('{{adminButton}}', adminButtonHtml || '')
                                                      .replace('{{userRole}}', userRole)
                                                      .replace('{{rows}}', rows);
                            res.writeHead(200, { 'Content-Type': 'text/html' });
                            res.end(processedHtml);
                        });
                    })
                    .catch(err => {
                        console.error('Error in route /:', err.message);
                        res.writeHead(500, { 'Content-Type': 'text/plain' });
                        res.end('Error loading index.html: ' + err.message);
                    });
            } else {
                console.log('Redirecting to /login');
                res.writeHead(302, { 'Location': '/login' });
                res.end();
            }
        } else if (req.url === '/admin.html' && req.method === 'GET') {
            if (isAuthenticated(req) && req.session.role === 'admin') {
                fs.promises.readFile(path.join(__dirname, 'admin.html'), 'utf8')
                    .then(html => {
                        return getUserHtmlRows().then(userRows => {
                            const processedHtml = html.replace('{{userRows}}', userRows);
                            res.writeHead(200, { 'Content-Type': 'text/html' });
                            res.end(processedHtml);
                        });
                    })
                    .catch(err => {
                        res.writeHead(500, { 'Content-Type': 'text/plain' });
                        res.end('Ошибка загрузки admin.html');
                    });
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
            req.on('end', () => {
                try {
                    const { login, password, isAdmin } = JSON.parse(body);
                    if (!login || !password) throw new Error('Логин и пароль обязательны');
                    const role = isAdmin === 'on' ? 'admin' : 'user';
                    const is_admin = role === 'admin' ? 1 : 0;
                    mysql.createConnection(dbConfig).then(connection => {
                        connection.execute('INSERT INTO users (login, password, is_admin, role) VALUES (?, ?, ?, ?)', [login, password, is_admin, role])
                            .then(() => {
                                connection.end();
                                res.writeHead(200, { 'Content-Type': 'application/json' });
                                res.end(JSON.stringify({ success: true }));
                            })
                            .catch(error => {
                                connection.end();
                                throw error;
                            });
                    }).catch(error => {
                        res.writeHead(400, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: false, error: error.message }));
                    });
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
            req.on('end', () => {
                try {
                    const { id } = JSON.parse(body);
                    if (!id) throw new Error('ID пользователя обязателен');
                    mysql.createConnection(dbConfig).then(connection => {
                        connection.execute('DELETE FROM users WHERE id = ?', [id])
                            .then(() => {
                                connection.end();
                                res.writeHead(200, { 'Content-Type': 'application/json' });
                                res.end(JSON.stringify({ success: true }));
                            })
                            .catch(error => {
                                connection.end();
                                throw error;
                            });
                    }).catch(error => {
                        res.writeHead(400, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: false, error: error.message }));
                    });
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
            req.on('end', () => {
                try {
                    const { id, login, password, isAdmin } = JSON.parse(body);
                    if (!id || !login || !password) throw new Error('ID, логин и пароль обязательны');
                    const role = isAdmin === 'on' ? 'admin' : 'user';
                    const is_admin = role === 'admin' ? 1 : 0;
                    mysql.createConnection(dbConfig).then(connection => {
                        connection.execute('UPDATE users SET login = ?, password = ?, is_admin = ?, role = ? WHERE id = ?', [login, password, is_admin, role, id])
                            .then(() => {
                                connection.end();
                                res.writeHead(200, { 'Content-Type': 'application/json' });
                                res.end(JSON.stringify({ success: true }));
                            })
                            .catch(error => {
                                connection.end();
                                throw error;
                            });
                    }).catch(error => {
                        res.writeHead(400, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: false, error: error.message }));
                    });
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
            req.on('end', () => {
                try {
                    const { id } = JSON.parse(body);
                    if (!id) throw new Error('ID пользователя обязателен');
                    mysql.createConnection(dbConfig).then(connection => {
                        connection.execute('SELECT password FROM users WHERE id = ?', [id])
                            .then(([rows]) => {
                                connection.end();
                                if (rows.length > 0) {
                                    res.writeHead(200, { 'Content-Type': 'application/json' });
                                    res.end(JSON.stringify({ success: true, password: rows[0].password }));
                                } else {
                                    res.writeHead(404, { 'Content-Type': 'application/json' });
                                    res.end(JSON.stringify({ success: false, error: 'Пользователь не найден' }));
                                }
                            })
                            .catch(error => {
                                connection.end();
                                throw error;
                            });
                    }).catch(error => {
                        res.writeHead(400, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: false, error: error.message }));
                    });
                } catch (error) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: error.message }));
                }
            });
        } else if (req.method === 'POST' && req.url === '/add') {
            isAuthenticatedOrToken(req).then(authenticated => {
                if (!authenticated) {
                    res.writeHead(401, { 'Content-Type': 'text/plain' });
                    res.end('Unauthorized');
                    return;
                }
                let body = '';
                req.on('data', chunk => { body += chunk; });
                req.on('end', () => {
                    try {
                        const { text } = JSON.parse(body);
                        if (!text) throw new Error("Текст не передан");
                        getUserIdFromRequest(req).then(userId => {
                            addItem(text, userId).then(newItemId => {
                                res.writeHead(200, { 'Content-Type': 'application/json' });
                                res.end(JSON.stringify({ success: true, id: newItemId }));
                            }).catch(error => {
                                res.writeHead(400, { 'Content-Type': 'application/json' });
                                res.end(JSON.stringify({ success: false, error: error.message }));
                            });
                        }).catch(error => {
                            res.writeHead(400, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ success: false, error: error.message }));
                        });
                    } catch (error) {
                        res.writeHead(400, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: false, error: error.message }));
                    }
                });
            });
        } else if (req.method === 'POST' && req.url === '/delete') {
            isAuthenticatedOrToken(req).then(authenticated => {
                if (!authenticated) {
                    res.writeHead(401, { 'Content-Type': 'text/plain' });
                    res.end('Unauthorized');
                    return;
                }
                let body = '';
                req.on('data', chunk => { body += chunk; });
                req.on('end', () => {
                    try {
                        const { id } = JSON.parse(body);
                        if (!id) throw new Error("ID не передан");
                        getUserIdFromRequest(req).then(userId => {
                            deleteItem(id, userId).then(() => {
                                res.writeHead(200, { 'Content-Type': 'application/json' });
                                res.end(JSON.stringify({ success: true }));
                            }).catch(error => {
                                res.writeHead(400, { 'Content-Type': 'application/json' });
                                res.end(JSON.stringify({ success: false, error: error.message }));
                            });
                        }).catch(error => {
                            res.writeHead(400, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ success: false, error: error.message }));
                        });
                    } catch (error) {
                        res.writeHead(400, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: false, error: error.message }));
                    }
                });
            });
        } else if (req.url.startsWith('/getItem') && req.method === 'GET') {
            if (!isAuthenticated(req)) {
                res.writeHead(401, { 'Content-Type': 'text/plain' });
                res.end('Unauthorized');
                return;
            }
            const urlParams = new URLSearchParams(req.url.split('?')[1]);
            const id = urlParams.get('id');
            const userId = req.session.userId;
            mysql.createConnection(dbConfig).then(connection => {
                connection.execute('SELECT text, order_index FROM items WHERE id = ? AND user_id = ?', [id, userId])
                    .then(([rows]) => {
                        connection.end();
                        if (rows.length > 0) {
                            res.writeHead(200, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ success: true, item: rows[0] }));
                        } else {
                            res.writeHead(404, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ success: false, error: 'Задача не найдена' }));
                        }
                    })
                    .catch(error => {
                        connection.end();
                        console.error('Ошибка:', error);
                        res.writeHead(500, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: false, error: 'Ошибка сервера' }));
                    });
            }).catch(error => {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'Ошибка сервера' }));
            });
        } else if (req.method === 'POST' && req.url === '/edit') {
            if (!isAuthenticated(req)) {
                res.writeHead(401, { 'Content-Type': 'text/plain' });
                res.end('Unauthorized');
                return;
            }
            let body = '';
            req.on('data', chunk => { body += chunk; });
            req.on('end', () => {
                try {
                    const { id, text, orderIndex } = JSON.parse(body);
                    if (!id || !text || orderIndex === undefined) throw new Error("ID, текст или порядок не переданы");
                    getUserIdFromRequest(req).then(userId => {
                        updateItem(id, text, orderIndex, userId).then(() => {
                            res.writeHead(200, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ success: true }));
                        }).catch(error => {
                            res.writeHead(400, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ success: false, error: error.message }));
                        });
                    }).catch(error => {
                        res.writeHead(400, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: false, error: error.message }));
                    });
                } catch (error) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: error.message }));
                }
            });
        } else if (req.method === 'POST' && req.url === '/reorder') {
            isAuthenticatedOrToken(req).then(authenticated => {
                if (!authenticated) {
                    res.writeHead(401, { 'Content-Type': 'text/plain' });
                    res.end('Unauthorized');
                    return;
                }
                let body = '';
                req.on('data', chunk => { body += chunk; });
                req.on('end', () => {
                    try {
                        const { id, newOrderIndex } = JSON.parse(body);
                        if (!id || newOrderIndex === undefined) throw new Error("ID или новый порядок не переданы");
                        getUserIdFromRequest(req).then(userId => {
                            reorderItem(id, newOrderIndex, userId).then(() => {
                                res.writeHead(200, { 'Content-Type': 'application/json' });
                                res.end(JSON.stringify({ success: true }));
                            }).catch(error => {
                                res.writeHead(400, { 'Content-Type': 'application/json' });
                                res.end(JSON.stringify({ success: false, error: error.message }));
                            });
                        }).catch(error => {
                            res.writeHead(400, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ success: false, error: error.message }));
                        });
                    } catch (error) {
                        res.writeHead(400, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: false, error: error.message }));
                    }
                });
            });
        } else if (req.method === 'POST' && req.url === '/logout') {
            req.session = null;
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true }));
        } else if (req.url === '/api/items' && req.method === 'GET') {
            const authHeader = req.headers['authorization'];
            if (authHeader && authHeader.startsWith('Bearer ')) {
                const token = authHeader.substring(7);
                mysql.createConnection(dbConfig).then(connection => {
                    connection.execute('SELECT id FROM users WHERE token = ?', [token])
                        .then(([rows]) => {
                            if (rows.length > 0) {
                                const userId = rows[0].id;
                                retrieveListItems(userId).then(items => {
                                    connection.end();
                                    res.writeHead(200, { 'Content-Type': 'application/json' });
                                    res.end(JSON.stringify(items));
                                }).catch(error => {
                                    connection.end();
                                    throw error;
                                });
                            } else {
                                connection.end();
                                res.writeHead(401, { 'Content-Type': 'text/plain' });
                                res.end('Unauthorized');
                            }
                        })
                        .catch(error => {
                            connection.end();
                            console.error('Ошибка:', error);
                            res.writeHead(500, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ success: false, error: 'Error retrieving items' }));
                        });
                }).catch(error => {
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'Ошибка сервера' }));
                });
            } else {
                res.writeHead(401, { 'Content-Type': 'text/plain' });
                res.end('Unauthorized');
            }
        } else if (req.method === 'POST' && req.url === '/moveUp') {
            isAuthenticatedOrToken(req).then(authenticated => {
                if (!authenticated) {
                    res.writeHead(401, { 'Content-Type': 'text/plain' });
                    res.end('Unauthorized');
                    return;
                }
                let body = '';
                req.on('data', chunk => { body += chunk; });
                req.on('end', () => {
                    try {
                        const { id } = JSON.parse(body);
                        if (!id) throw new Error("ID не передан");
                        getUserIdFromRequest(req).then(userId => {
                            moveUp(id, userId).then(() => {
                                res.writeHead(200, { 'Content-Type': 'application/json' });
                                res.end(JSON.stringify({ success: true }));
                            }).catch(error => {
                                res.writeHead(400, { 'Content-Type': 'application/json' });
                                res.end(JSON.stringify({ success: false, error: error.message }));
                            });
                        }).catch(error => {
                            res.writeHead(400, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ success: false, error: error.message }));
                        });
                    } catch (error) {
                        res.writeHead(400, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: false, error: error.message }));
                    }
                });
            });
        } else if (req.method === 'POST' && req.url === '/moveDown') {
            isAuthenticatedOrToken(req).then(authenticated => {
                if (!authenticated) {
                    res.writeHead(401, { 'Content-Type': 'text/plain' });
                    res.end('Unauthorized');
                    return;
                }
                let body = '';
                req.on('data', chunk => { body += chunk; });
                req.on('end', () => {
                    try {
                        const { id } = JSON.parse(body);
                        if (!id) throw new Error("ID не передан");
                        getUserIdFromRequest(req).then(userId => {
                            moveDown(id, userId).then(() => {
                                res.writeHead(200, { 'Content-Type': 'application/json' });
                                res.end(JSON.stringify({ success: true }));
                            }).catch(error => {
                                res.writeHead(400, { 'Content-Type': 'application/json' });
                                res.end(JSON.stringify({ success: false, error: error.message }));
                            });
                        }).catch(error => {
                            res.writeHead(400, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ success: false, error: error.message }));
                        });
                    } catch (error) {
                        res.writeHead(400, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: false, error: error.message }));
                    }
                });
            });
        } else {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('Route not found');
        }
    });
}

// Добавление задачи
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

// Изменение порядка задач
async function reorderItem(id, newOrderIndex, userId) {
    try {
        const connection = await mysql.createConnection(dbConfig);
        const [currentItem] = await connection.execute('SELECT order_index FROM items WHERE id = ? AND user_id = ?', [id, userId]);
        if (currentItem.length === 0) throw new Error('Задача не найдена');
        const currentOrderIndex = currentItem[0].order_index;

        if (newOrderIndex > currentOrderIndex) {
            await connection.execute('UPDATE items SET order_index = order_index - 1 WHERE user_id = ? AND order_index > ? AND order_index <= ?', [userId, currentOrderIndex, newOrderIndex]);
        } else if (newOrderIndex < currentOrderIndex) {
            await connection.execute('UPDATE items SET order_index = order_index + 1 WHERE user_id = ? AND order_index >= ? AND order_index < ?', [userId, newOrderIndex, currentOrderIndex]);
        }
        await connection.execute('UPDATE items SET order_index = ? WHERE id = ? AND user_id = ?', [newOrderIndex, id, userId]);
        await connection.end();
        await rebuildOrderIndex(userId);
    } catch (error) {
        console.error('Error reordering item:', error);
        throw error;
    }
}

// Удаление задачи
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

// Обновление задачи
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

// Перемещение задачи вверх
const moveUp = async (id, userId) => {
    await executeWithRetry(async () => {
        const connection = await pool.getConnection();
        try {
            await connection.beginTransaction();
            const [itemRows] = await connection.execute('SELECT order_index FROM items WHERE id = ? AND user_id = ? FOR UPDATE', [id, userId]);
            if (!itemRows.length) throw new Error('Item not found');
            const currentOrderIndex = itemRows[0].order_index;
            const [aboveRows] = await connection.execute('SELECT id, order_index FROM items WHERE user_id = ? AND order_index < ? ORDER BY order_index DESC LIMIT 1 FOR UPDATE', [userId, currentOrderIndex]);
            if (!aboveRows.length) throw new Error('No item above to swap with');
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
            const [itemRows] = await connection.execute('SELECT order_index FROM items WHERE id = ? AND user_id = ? FOR UPDATE', [id, userId]);
            if (!itemRows.length) throw new Error('Item not found');
            const currentOrderIndex = itemRows[0].order_index;
            const [belowRows] = await connection.execute('SELECT id, order_index FROM items WHERE user_id = ? AND order_index > ? ORDER BY order_index ASC LIMIT 1 FOR UPDATE', [userId, currentOrderIndex]);
            if (!belowRows.length) throw new Error('No item below to swap with');
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
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
