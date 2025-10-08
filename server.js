const express = require('express');
const path = require('path');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// reCAPTCHA секретный ключ (тестовый ключ для разработки)
const RECAPTCHA_SECRET_KEY = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe';

// Хранилище пользователей (в реальном приложении используйте базу данных)
const users = new Map();

// Проверка reCAPTCHA
async function verifyRecaptcha(recaptchaResponse) {
    try {
        const response = await axios.post('https://www.google.com/recaptcha/api/siteverify', null, {
            params: {
                secret: RECAPTCHA_SECRET_KEY,
                response: recaptchaResponse
            }
        });
        
        return response.data.success;
    } catch (error) {
        console.error('Ошибка проверки reCAPTCHA:', error);
        return false;
    }
}

// Маршруты
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.post('/register', async (req, res) => {
    try {
        const { username, password, 'g-recaptcha-response': recaptchaResponse } = req.body;

        // Валидация данных
        if (!username || !password || !recaptchaResponse) {
            return res.status(400).json({ 
                error: 'Все поля обязательны для заполнения' 
            });
        }

        if (username.length < 3 || username.length > 20) {
            return res.status(400).json({ 
                error: 'Имя пользователя должно быть от 3 до 20 символов' 
            });
        }

        if (password.length < 6) {
            return res.status(400).json({ 
                error: 'Пароль должен содержать минимум 6 символов' 
            });
        }

        // Проверка reCAPTCHA
        const isRecaptchaValid = await verifyRecaptcha(recaptchaResponse);
        
        if (!isRecaptchaValid) {
            return res.status(400).json({ 
                error: 'Проверка reCAPTCHA не пройдена' 
            });
        }

        // Проверка существующего пользователя
        if (users.has(username)) {
            return res.status(400).json({ 
                error: 'Пользователь с таким именем уже существует' 
            });
        }

        // Сохранение пользователя (в реальном приложении хэшируйте пароль!)
        users.set(username, {
            username,
            password, // В реальном приложении используйте bcrypt для хэширования!
            registeredAt: new Date().toISOString()
        });

        console.log(`Новый пользователь зарегистрирован: ${username}`);

        res.json({ 
            success: true, 
            message: 'Регистрация успешна!',
            redirectUrl: 'https://t.me/wounsee'
        });

    } catch (error) {
        console.error('Ошибка регистрации:', error);
        res.status(500).json({ 
            error: 'Внутренняя ошибка сервера' 
        });
    }
});

// Маршрут для получения списка пользователей (для отладки)
app.get('/users', (req, res) => {
    if (process.env.NODE_ENV === 'production') {
        return res.status(403).json({ error: 'Доступ запрещен' });
    }
    
    const usersArray = Array.from(users.values()).map(user => ({
        username: user.username,
        registeredAt: user.registeredAt
    }));
    
    res.json(usersArray);
});

// Обработка 404
app.use((req, res) => {
    res.status(404).json({ error: 'Страница не найдена' });
});

// Обработка ошибок
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Что-то пошло не так!' });
});

app.listen(PORT, () => {
    console.log(`Сервер запущен на порту ${PORT}`);
    console.log(`Откройте http://localhost:${PORT} в браузере`);
});
