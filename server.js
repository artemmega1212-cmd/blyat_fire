const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const { OAuth2Client } = require('google-auth-library');
const marked = require('marked');
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

const app = express();
const PORT = process.env.PORT || 3000;

// PostgreSQL connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgresql://username:password@localhost:5432/wounsee_forum',
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Google OAuth
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// File upload configuration
const storage = multer.diskStorage({
    destination: 'uploads/',
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
    fileFilter: (req, file, cb) => {
        // Basic file type validation
        const allowedTypes = /jpeg|jpg|png|gif|pdf|doc|docx|txt|zip/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Недопустимый тип файла'));
        }
    }
});

// Middleware
app.use(express.json());
app.use(express.static('.'));
app.use('/uploads', express.static('uploads'));

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Initialize database
async function initDatabase() {
    try {
        // Users table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                google_id VARCHAR(255) UNIQUE,
                email VARCHAR(255) UNIQUE NOT NULL,
                name VARCHAR(255) NOT NULL,
                avatar VARCHAR(500),
                role VARCHAR(50) DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Categories table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS categories (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                icon VARCHAR(100),
                created_by INTEGER REFERENCES users(id),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Posts table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS posts (
                id SERIAL PRIMARY KEY,
                title VARCHAR(500) NOT NULL,
                content TEXT NOT NULL,
                category_id INTEGER REFERENCES categories(id),
                author_id INTEGER REFERENCES users(id),
                file_path VARCHAR(500),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Comments table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS comments (
                id SERIAL PRIMARY KEY,
                content TEXT NOT NULL,
                post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
                author_id INTEGER REFERENCES users(id),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Create default admin user
        const adminResult = await pool.query(
            'SELECT * FROM users WHERE email = $1 OR name IN ($2, $3)',
            ['admin@wounsee.com', 'wounsee', 'Wounsee']
        );

        if (adminResult.rows.length === 0) {
            await pool.query(
                'INSERT INTO users (email, name, role) VALUES ($1, $2, $3)',
                ['admin@wounsee.com', 'Wounsee', 'admin']
            );
            console.log('Default admin user created');
        }

        // Create default category
        const categoryResult = await pool.query('SELECT * FROM categories WHERE name = $1', ['Прочее']);
        if (categoryResult.rows.length === 0) {
            await pool.query(
                'INSERT INTO categories (name, description, icon) VALUES ($1, $2, $3)',
                ['Прочее', 'Обсуждения, не подходящие под другие категории', 'fa-ellipsis-h']
            );
        }

        console.log('Database initialized successfully');
    } catch (error) {
        console.error('Database initialization failed:', error);
    }
}

// Auth middleware
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Требуется авторизация' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [decoded.userId]);
        
        if (userResult.rows.length === 0) {
            return res.status(401).json({ error: 'Пользователь не найден' });
        }

        req.user = userResult.rows[0];
        next();
    } catch (error) {
        res.status(403).json({ error: 'Недействительный токен' });
    }
};

// Admin middleware
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Требуются права администратора' });
    }
    next();
};

// Markdown sanitization
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

function sanitizeMarkdown(content) {
    const html = marked.parse(content);
    return DOMPurify.sanitize(html);
}

// Routes

// Google OAuth
app.post('/auth/google', async (req, res) => {
    try {
        const { token } = req.body;
        const ticket = await googleClient.verifyIdToken({
            idToken: token,
            audience: process.env.GOOGLE_CLIENT_ID
        });

        const payload = ticket.getPayload();
        
        // Check if user exists
        let userResult = await pool.query(
            'SELECT * FROM users WHERE google_id = $1 OR email = $2',
            [payload.sub, payload.email]
        );

        let user;
        
        if (userResult.rows.length === 0) {
            // Create new user
            userResult = await pool.query(
                `INSERT INTO users (google_id, email, name, avatar, role) 
                 VALUES ($1, $2, $3, $4, $5) 
                 RETURNING id, email, name, avatar, role`,
                [payload.sub, payload.email, payload.name, payload.picture, 'user']
            );
            user = userResult.rows[0];
        } else {
            user = userResult.rows[0];
            
            // Update user info
            await pool.query(
                'UPDATE users SET name = $1, avatar = $2 WHERE id = $3',
                [payload.name, payload.picture, user.id]
            );
            
            user.name = payload.name;
            user.avatar = payload.picture;
        }

        const jwtToken = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });

        res.json({
            success: true,
            token: jwtToken,
            user: {
                id: user.id,
                email: user.email,
                name: user.name,
                avatar: user.avatar,
                role: user.role
            }
        });
    } catch (error) {
        console.error('Google auth error:', error);
        res.status(400).json({ success: false, error: 'Ошибка аутентификации' });
    }
});

// Verify token
app.get('/auth/verify', authenticateToken, (req, res) => {
    res.json({
        success: true,
        user: {
            id: req.user.id,
            email: req.user.email,
            name: req.user.name,
            avatar: req.user.avatar,
            role: req.user.role
        }
    });
});

// Categories
app.get('/api/categories', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT c.*, COUNT(p.id) as post_count
            FROM categories c
            LEFT JOIN posts p ON p.category_id = c.id
            GROUP BY c.id
            ORDER BY c.name
        `);
        res.json(result.rows);
    } catch (error) {
        console.error('Categories error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Posts
app.get('/api/posts', async (req, res) => {
    try {
        const { sort = 'newest', limit = 10, category } = req.query;
        
        let orderBy = 'p.created_at DESC';
        if (sort === 'popular') orderBy = 'p.comment_count DESC';
        if (sort === 'commented') orderBy = 'p.comment_count DESC';
        
        let query = `
            SELECT p.*, 
                   c.name as category_name,
                   u.name as author_name,
                   COUNT(cm.id) as comment_count
            FROM posts p
            LEFT JOIN categories c ON p.category_id = c.id
            LEFT JOIN users u ON p.author_id = u.id
            LEFT JOIN comments cm ON cm.post_id = p.id
            ${category ? 'WHERE p.category_id = $1' : ''}
            GROUP BY p.id, c.name, u.name
            ORDER BY ${orderBy}
            LIMIT ${parseInt(limit)}
        `;
        
        const params = category ? [category] : [];
        const result = await pool.query(query, params);
        
        res.json(result.rows);
    } catch (error) {
        console.error('Posts error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Create post
app.post('/api/posts', authenticateToken, upload.single('file'), async (req, res) => {
    try {
        const { title, content, category_id } = req.body;
        
        if (!title || !content || !category_id) {
            return res.status(400).json({ error: 'Все поля обязательны' });
        }

        const sanitizedContent = sanitizeMarkdown(content);
        const filePath = req.file ? req.file.path : null;

        const result = await pool.query(
            `INSERT INTO posts (title, content, category_id, author_id, file_path)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING *`,
            [title, sanitizedContent, category_id, req.user.id, filePath]
        );

        res.json({ success: true, post: result.rows[0] });
    } catch (error) {
        console.error('Create post error:', error);
        res.status(500).json({ error: 'Ошибка при создании поста' });
    }
});

// Admin routes
app.get('/api/admin/categories', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM categories ORDER BY name');
        res.json(result.rows);
    } catch (error) {
        console.error('Admin categories error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/admin/categories', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { name, description, icon } = req.body;
        
        const result = await pool.query(
            'INSERT INTO categories (name, description, icon, created_by) VALUES ($1, $2, $3, $4) RETURNING *',
            [name, description, icon || 'fa-folder', req.user.id]
        );

        res.json({ success: true, category: result.rows[0] });
    } catch (error) {
        console.error('Create category error:', error);
        res.status(500).json({ error: 'Ошибка при создании категории' });
    }
});

// Serve index.html for all other routes
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Start server
async function startServer() {
    await initDatabase();
    
    app.listen(PORT, () => {
        console.log(`🚀 Wounsee Forum запущен на порту ${PORT}`);
        console.log(`📍 Откройте http://localhost:${PORT} в браузере`);
    });
}

startServer().catch(console.error);
