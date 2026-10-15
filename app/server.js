require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const pool = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// --- TRASY FORMULARZY I WIDOKÓW ---
app.get('/', (req, res) => res.redirect('/login'));
app.get('/login', (req, res) => res.render('login', { error: null }));
app.get('/register', (req, res) => res.render('register', { error: null }));
app.get('/reset-request', (req, res) => res.render('reset-request', { error: null, success: null }));

// --- REJESTRACJA Z BEZPIECZNYM HASZOWANIEM ---
app.post('/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password || password.length < 6) {
        return res.render('register', { error: 'Podaj poprawny e-mail i hasło (min. 6 znaków).' });
    }

    try {
        const userCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userCheck.rows.length > 0) {
            return res.render('register', { error: 'Użytkownik już istnieje.' });
        }

        // Bezpieczny algorytm hashowania (bcrypt)
        const hashedPassword = await bcrypt.hash(password, 12);
        await pool.query('INSERT INTO users (email, password) VALUES ($1, $2)', [email, hashedPassword]);

        res.redirect('/login');
    } catch (err) {
        console.error(err);
        res.render('register', { error: 'Błąd serwera.' });
    }
});

// --- LOGOWANIE (JWT: Krótki Access Token + Refresh Token w HttpOnly Cookie) ---
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) return res.render('login', { error: 'Błędne dane logowania.' });

        const user = result.rows[0];
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.render('login', { error: 'Błędne dane logowania.' });

        // Krótki czas życia tokenu dostępu (np. 15 minut)
        const accessToken = jwt.sign({ userId: user.id, email: user.email }, process.env.JWT_ACCESS_SECRET, { expiresIn: '15m' });
        
        // Refresh token o dłuższym życiu
        const refreshToken = jwt.sign({ userId: user.id }, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });

        // Zapisanie refresh tokenu w bezpiecznym ciasteczku HttpOnly
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        // Przekazanie access tokenu do przeglądarki (np. w nagłówku lub skrypcie początkowym)
        res.send(`
            <script>
                // Przechowywanie access tokenu w pamięci przeglądarki (zgodnie z wymaganiem)
                sessionStorage.setItem('accessToken', '${accessToken}');
                window.location.href = '/dashboard';
            </script>
        `);
    } catch (err) {
        console.error(err);
        res.render('login', { error: 'Błąd logowania.' });
    }
});

// --- ENDPOINT DO ODŚWIEŻANIA TOKENU (REFRESH) ---
app.post('/api/refresh', async (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) return res.status(401).json({ error: 'Brak refresh tokenu' });

    jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, async (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Nieprawidłowy refresh token' });

        try {
            const result = await pool.query('SELECT * FROM users WHERE id = $1', [decoded.userId]);
            if (result.rows.length === 0) return res.status(403).json({ error: 'Użytkownik nie istnieje' });

            const user = result.rows[0];
            const newAccessToken = jwt.sign({ userId: user.id, email: user.email }, process.env.JWT_ACCESS_SECRET, { expiresIn: '15m' });
            
            res.json({ accessToken: newAccessToken });
        } catch (dbErr) {
            res.status(500).json({ error: 'Błąd bazy danych' });
        }
    });
});

// --- CHRONIONY PANEL DLA ZALOGOWANYCH ---
app.get('/dashboard', (req, res) => {
    // Serwer renderuje widok, a klient sprawdza token w sessionStorage przez JavaScript
    res.render('dashboard');
});

// --- RESET HASŁA W OPARCIU O JEDNORAZOWY TOKEN ---
app.post('/reset-request', async (req, res) => {
    const { email } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) {
            return res.render('reset-request', { error: null, success: 'Jeśli e-mail istnieje, link resetujący został wysłany.' });
        }

        const resetToken = jwt.sign({ email }, process.env.JWT_ACCESS_SECRET, { expiresIn: '15m' });
        const expires = new Date(Date.now() + 15 * 60 * 1000);

        await pool.query('UPDATE users SET reset_token = $1, reset_token_expires = $2 WHERE email = $3', [resetToken, expires, email]);

        // W celach demonstracyjnych laboratoriów wyświetlamy link bezpośrednio
        res.render('reset-request', { error: null, success: `Link resetujący (symulacja wysyłki): /reset-password?token=${resetToken}` });
    } catch (err) {
        res.render('reset-request', { error: 'Wystąpił błąd.', success: null });
    }
});

// --- WYLOGOWANIE ---
app.get('/logout', (req, res) => {
    res.clearCookie('refreshToken');
    res.redirect('/login');
});

app.listen(PORT, () => {
    console.log(`Serwer działa na http://localhost:${PORT}`);
});

