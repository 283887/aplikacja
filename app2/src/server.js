const crypto = require("crypto");
const validator = require('validator');
const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const otplib = require('otplib');
const authenticator = otplib.authenticator || otplib;
const QRCode = require('qrcode');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const sanitizeHtml = require('sanitize-html');

const prisma = new PrismaClient();
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'tajny_klucz_jwt';

// Konfiguracja widoków EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '../public')));

//Limit błędnych logowań
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minut
    max: 5, // max 5 zapytań z jednego IP
    skipSuccessfulRequests: true, // NIE zliczaj udanych logowań (status < 400)
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        res.status(429).render('login', {
            error: 'Zbyt wiele prób logowania. Odczekaj 15 minut przed kolejną próbą.',
            success: null
        });
    }
});

// Konfiguracja Multer (upload zdjęć profilowych, ograniczenie rozmiaru do 2MB i filtr rozszerzeń)
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, path.join(__dirname, '../public/uploads'));
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'avatar-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const fileFilter = (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);

    if (extname && mimetype) {
        return cb(null, true);
    } else {
        cb(new Error('Niedozwolony format pliku! Dozwolone są wyłącznie pliki graficzne (jpg, jpeg, png, gif).'));
    }
};

const upload = multer({
    storage: storage,
    limits: { fileSize: 2 * 1024 * 1024 }, // Limit wielkości: max 2 MB
    fileFilter: fileFilter
});

// --- POMOCNICZY MIDDLEWARE: Sprawdzanie zalogowanego użytkownika z ciasteczka ---
const checkAuth = async (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        req.user = null;
        return next();
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await prisma.user.findUnique({ where: { id: decoded.userId } });
        req.user = user || null;
    } catch (err) {
        req.user = null;
    }
    next();
};

app.use(checkAuth);

// --- TRASY APLIKACJI ---

// 1. Strona główna (wyświetlanie filmów i wyszukiwarka)
app.get('/', async (req, res) => {
    try {
        const search = req.query.search || '';
        const movies = await prisma.movie.findMany({
            where: {
                OR: [
                    { title: { contains: search, mode: 'insensitive' } },
                    { director: { contains: search, mode: 'insensitive' } },
                ]
            }
        });

        res.render('index', { user: req.user, movies, searchTerm: search });
    } catch (err) {
        console.error(err);
        res.status(500).send("Błąd serwera");
    }
});

// 2. Widok logowania / rejestracji
app.get('/login', (req, res) => {
    if (req.user) return res.redirect('/');
    res.render('login', { error: null, success: null });
});

// 3. Obsługa Rejestracji
app.post('/auth/register', async (req, res) => {
    try {
        let { username, email, password } = req.body;

        username = (username || '').trim();
        email = (email || '').trim().toLowerCase();
        password = password || '';

        if (!username || !email || !password) {
            return res.render('login', { error: 'Wszystkie pola są wymagane!', success: null });
        }

        if (!validator.isEmail(email)) {
            return res.render('login', { error: 'Podaj poprawny adres e-mail (np. user@domena.pl).', success: null });
        }

        if (username.length < 3 || username.length > 25) {
            return res.render('login', { 
                error: 'Nazwa użytkownika musi mieć od 3 do 25 znaków.', 
                success: null 
            });
        }

        const passwordPolicy = { minLength: 8, minUppercase: 1, minNumbers: 1, minSymbols: 0 };
        if (!validator.isStrongPassword(password, passwordPolicy)) {
            return res.render('login', { 
                error: 'Hasło musi mieć co najmniej 8 znaków, zawierać przynajmniej jedną wielką literę i jedną cyfrę.', 
                success: null 
            });
        }

        const existingUser = await prisma.user.findFirst({
            where: { OR: [{ email }, { username }] }
        });

        if (existingUser) {
            return res.render('login', { error: 'Użytkownik o takim e-mailu lub nazwie już istnieje.', success: null });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        await prisma.user.create({
            data: { username, email, password: hashedPassword }
        });

        res.render('login', { error: null, success: 'Konto zostało utworzone pomyślnie! Możesz się teraz zalogować.' });
    } catch (err) {
        console.error(err);
        res.render('login', { error: 'Wystąpił błąd podczas rejestracji.', success: null });
    }
});

// 4. Obsługa Logowania
app.post('/auth/login', authLimiter, async (req, res) => {
    try {
        const { identifier, password } = req.body;

        const user = await prisma.user.findFirst({
            where: { OR: [{ email: identifier }, { username: identifier }] }
        });

        if (!user) {
            return res.status(400).render('login', { error: 'Nieprawidłowy login lub hasło.', success: null });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).render('login', { error: 'Nieprawidłowy login lub hasło.', success: null });
        }

        if (user.isTwoFactorEnabled) {
            res.clearCookie('token');
            const pendingToken = jwt.sign({ userId: user.id, is2faPending: true }, JWT_SECRET, { expiresIn: '5m' });
            res.cookie('pending_2fa', pendingToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'lax',
                maxAge: 5 * 60 * 1000
            });
            return res.redirect('/auth/2fa/verify');
        }

        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '10m' });

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 10 * 60 * 1000
        });

        res.redirect('/');
    } catch (err) {
        console.error(err);
        res.render('login', { error: 'Wystąpił błąd podczas logowania.', success: null });
    }
});

// 5. Wylogowanie
app.get('/auth/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/');
});

// Resetowanie hasła
app.post('/auth/enter-token', (req, res) => {
    const token = (req.body.token || '').trim();
    if (!token) {
        return res.render('forgot-password', { error: 'Wprowadź token resetujący.', success: null });
    }
    res.redirect('/auth/reset-password/' + encodeURIComponent(token));
});

app.get(['/forgot-password', '/auth/forgot-password'], (req, res) => {
    res.render('forgot-password', { error: null, success: null });
});

app.post('/auth/forgot-password', async (req, res) => {
    try {
        const email = (req.body.email || '').trim().toLowerCase();
        const user = await prisma.user.findUnique({ where: { email } });

        if (!user) {
            return res.render('forgot-password', {
                error: null,
                success: 'Jeśli podany adres istnieje w systemie, link do resetu hasła został wygenerowany.'
            });
        }

        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetTokenExpiry = new Date(Date.now() + 15 * 60 * 1000);

        await prisma.user.update({
            where: { id: user.id },
            data: { resetToken, resetTokenExpiry }
        });

        const resetUrl = `http://localhost:3000/auth/reset-password/${resetToken}`;
        console.log('================================================================');
        console.log(`[RESET HASŁA] Dane dla: ${email}`);
        console.log(`[TOKEN] ${resetToken}`);
        console.log(resetUrl);
        console.log('================================================================');

        res.render('forgot-password', {
            error: null,
            success: 'Jeśli podany adres istnieje w systemie, link do resetu hasła został wygenerowany (sprawdź konsolę serwera).'
        });
    } catch (err) {
        console.error(err);
        res.render('forgot-password', { error: 'Wystąpił błąd serwera.', success: null });
    }
});

app.get('/auth/reset-password/:token', async (req, res) => {
    try {
        const { token } = req.params;
        const user = await prisma.user.findFirst({
            where: {
                resetToken: token,
                resetTokenExpiry: { gt: new Date() }
            }
        });

        if (!user) {
            return res.render('login', { error: 'Token resetowania hasła jest nieprawidłowy lub wygasł.', success: null });
        }

        res.render('reset-password', { token, error: null });
    } catch (err) {
        console.error(err);
        res.redirect('/login');
    }
});

app.post('/auth/reset-password/:token', async (req, res) => {
    try {
        const { token } = req.params;
        const password = req.body.password || '';

        const user = await prisma.user.findFirst({
            where: {
                resetToken: token,
                resetTokenExpiry: { gt: new Date() }
            }
        });

        if (!user) {
            return res.render('login', { error: 'Token resetowania hasła jest nieprawidłowy lub wygasł.', success: null });
        }

        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
        if (!passwordRegex.test(password)) {
            return res.render('reset-password', {
                token,
                error: 'Hasło musi mieć co najmniej 8 znaków, zawierać dużą literę oraz cyfrę.'
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await prisma.user.update({
            where: { id: user.id },
            data: {
                password: hashedPassword,
                resetToken: null,
                resetTokenExpiry: null
            }
        });

        res.render('login', { error: null, success: 'Hasło zostało pomyślnie zmienione. Możesz się zalogować.' });
    } catch (err) {
        console.error(err);
        res.render('reset-password', { token: req.params.token, error: 'Wystąpił błąd podczas zmiany hasła.' });
    }
});

// 6. Menu użytkownika
app.get('/user/menu', (req, res) => {
    if (!req.user) return res.redirect('/login');
    res.render('userMenu', { user: req.user, error: null, success: null });
});

// Zmiana nazwy użytkownika
app.post('/user/update-username', checkAuth, async (req, res) => {
    if (!req.user) return res.redirect('/login');
    try {
        const newUsername = (req.body.newUsername || req.body.username || '').trim();

        if (newUsername.length < 3 || newUsername.length > 25) {
            return res.render('userMenu', { 
                user: req.user, 
                error: 'Nazwa użytkownika musi mieć od 3 do 25 znaków.', 
                success: null 
            });
        }

        const isValidFormat = /^[a-zA-Z0-9_ -]+$/.test(newUsername);
        if (!isValidFormat) {
            return res.render('userMenu', { 
                user: req.user, 
                error: 'Nazwa użytkownika może zawierać tylko litery, cyfry, spacje, myślniki i podkreślenia.', 
                success: null 
            });
        }

        const existing = await prisma.user.findFirst({ 
            where: { 
                username: newUsername,
                NOT: { id: req.user.id } 
            } 
        });

        if (existing) {
            return res.render('userMenu', { 
                user: req.user, 
                error: 'Ta nazwa użytkownika jest już zajęta.', 
                success: null 
            });
        }

        const updatedUser = await prisma.user.update({
            where: { id: req.user.id },
            data: { username: newUsername }
        });

        res.render('userMenu', { 
            user: updatedUser, 
            error: null, 
            success: 'Nazwa użytkownika została zaktualizowana!' 
        });
    } catch (err) {
        console.error(err);
        res.render('userMenu', { 
            user: req.user, 
            error: 'Wystąpił błąd podczas zmiany nazwy.', 
            success: null 
        });
    }
});

// Zmiana hasła z poziomu menu użytkownika
app.post('/user/update-password', checkAuth, async (req, res) => {
    if (!req.user) return res.redirect('/login');
    try {
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.render('userMenu', { user: req.user, error: 'Wszystkie pola hasła są wymagane.', success: null });
        }

        const isMatch = await bcrypt.compare(currentPassword, req.user.password);
        if (!isMatch) {
            return res.render('userMenu', { user: req.user, error: 'Obecne hasło jest nieprawidłowe.', success: null });
        }

        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
        if (!passwordRegex.test(newPassword)) {
            return res.render('userMenu', { user: req.user, error: 'Nowe hasło musi mieć min. 8 znaków, dużą literę i cyfrę.', success: null });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        const updatedUser = await prisma.user.update({
            where: { id: req.user.id },
            data: { password: hashedPassword }
        });

        res.render('userMenu', { user: updatedUser, error: null, success: 'Hasło zostało zmienione pomyślnie!' });
    } catch (err) {
        console.error(err);
        res.render('userMenu', { user: req.user, error: 'Błąd podczas zmiany hasła.', success: null });
    }
});

// Endpoint do przesyłania zdjęcia profilowego
app.post('/user/upload-avatar', checkAuth, (req, res) => {
    if (!req.user) return res.redirect('/login');
    
    upload.single('avatar')(req, res, async (err) => {
        if (err) {
            return res.render('userMenu', { 
                user: req.user, 
                error: err.message, 
                success: null 
            });
        }
        
        try {
            if (!req.file) {
                return res.render('userMenu', { 
                    user: req.user, 
                    error: 'Nie wybrano żadnego pliku.', 
                    success: null 
                });
            }

            const imagePath = '/uploads/' + req.file.filename;

            const updatedUser = await prisma.user.update({
                where: { id: req.user.id },
                data: { profileImage: imagePath }
            });

            res.render('userMenu', { 
                user: updatedUser, 
                error: null, 
                success: 'Zdjęcie profilowe zostało pomyślnie zaktualizowane!' 
            });
        } catch (dbErr) {
            console.error(dbErr);
            res.render('userMenu', { 
                user: req.user, 
                error: 'Wystąpił błąd podczas zapisu w bazie danych.', 
                success: null 
            });
        }
    });
});

// Endpoint do usuwania zdjęcia profilowego
app.post('/user/delete-avatar', checkAuth, async (req, res) => {
    if (!req.user) return res.redirect('/login');
    try {
        const updatedUser = await prisma.user.update({
            where: { id: req.user.id },
            data: { profileImage: null }
        });

        res.render('userMenu', { 
            user: updatedUser, 
            error: null, 
            success: 'Zdjęcie profilowe zostało usunięte.' 
        });
    } catch (err) {
        console.error(err);
        res.render('userMenu', { 
            user: req.user, 
            error: 'Wystąpił błąd podczas usuwania zdjęcia.', 
            success: null 
        });
    }
});

// 7. Usuwanie konta użytkownika
app.post('/user/delete', async (req, res) => {
    if (!req.user) return res.redirect('/login');
    try {
        await prisma.rating.deleteMany({ where: { userId: req.user.id } });
        await prisma.comment.deleteMany({ where: { userId: req.user.id } });
        await prisma.user.delete({ where: { id: req.user.id } });

        res.clearCookie('token');
        res.redirect('/');
    } catch (err) {
        console.error(err);
        res.redirect('/user/menu');
    }
});

// emotki
app.post('/comments/:commentId/reactions', async (req, res) => {
    if (!req.user) return res.redirect('/login');

    try {
        const commentId = parseInt(req.params.commentId);
        const allowed = ['👍', '❤️', '😂', '😮', '👎'];
        const type = String(req.body.type || '').trim();

        if (!allowed.includes(type)) {
            return res.redirect('back');
        }

        await prisma.commentReaction.upsert({
            where: {
                userId_commentId: {
                    userId: req.user.id,
                    commentId
                }
            },
            update: { type },
            create: {
                type,
                userId: req.user.id,
                commentId
            }
        });

        res.redirect('back');
    } catch (err) {
        console.error(err);
        res.redirect('back');
    }
});
// 8. Szczegóły filmu, oceny i komentarze
app.get('/movies/:id', async (req, res) => {
    try {
        const movieId = parseInt(req.params.id);
        const movie = await prisma.movie.findUnique({
            where: { id: movieId },
            include: {
                ratings: true,
                comments: {
                    where: { parentId: null },
                    include: {
                        user: true,
                        replies: {
                            include: { user: true },
                            orderBy: { createdAt: 'asc' }
                        },
                        reactions: {
                            include: { user: true }
                        }
                    },
                    orderBy: { createdAt: 'desc' }
                }
            }
        });

        if (!movie) return res.status(404).send("Film nie został znaleziony");

        let userRating = null;
        if (req.user) {
            userRating = await prisma.rating.findUnique({
                where: {
                    userId_movieId: { userId: req.user.id, movieId: movieId }
                }
            });
        }

        const commentsWithUserReaction = (movie.comments || []).map(comment => {
            const userReaction = req.user
                ? (comment.reactions || []).find(r => r.userId === req.user.id)?.type || null
                : null;

            return {
                ...comment,
                userReaction
            };
        });

        res.render('movie', {
            user: req.user,
            movie,
            comments: commentsWithUserReaction,
            userRating,
            error: null,
            success: null
        });
    } catch (err) {
        console.error(err);
        res.status(500).send("Błąd serwera");
    }
});

// 9. System oceniania (1 ocena 1-10 na użytkownika per film)
app.post('/movies/:id/rate', async (req, res) => {
    if (!req.user) return res.redirect('/login');
    try {
        const movieId = parseInt(req.params.id);
        const value = parseInt(req.body.value);

        await prisma.rating.upsert({
            where: { userId_movieId: { userId: req.user.id, movieId } },
            update: { value },
            create: { value, userId: req.user.id, movieId }
        });

        const allRatings = await prisma.rating.findMany({ where: { movieId } });
        const avg = allRatings.reduce((sum, r) => sum + r.value, 0) / allRatings.length;

        await prisma.movie.update({
            where: { id: movieId },
            data: { averageRating: avg }
        });

        res.redirect(`/movies/${movieId}`);
    } catch (err) {
        console.error(err);
        res.redirect(`/movies/${req.params.id}`);
    }
});

// 10. System komentarzy i odpowiedzi (wątkowanie)
app.post('/movies/:id/comments', async (req, res) => {
    if (!req.user) return res.redirect('/login');
    try {
        const movieId = parseInt(req.params.id);
        const { content, parentId } = req.body;

// Sanityzacja: dozwolone tylko proste tagi formatowania tekstu
        const cleanContent = sanitizeHtml(req.body.content || '', {
            allowedTags: ['b', 'i', 'em', 'strong', 'a'],
            allowedAttributes: { 'a': ['href'] }
        }).trim();

        if (!cleanContent) {
            return res.redirect(`/movies/${movieId}`);
        }

        await prisma.comment.create({
            data: {
                content: cleanContent,
                userId: req.user.id,
                movieId,
                parentId: parentId ? parseInt(parentId) : null
            }
        });

        res.redirect(`/movies/${movieId}`);
    } catch (err) {
        console.error(err);
        res.redirect(`/movies/${req.params.id}`);
    }
});

// Edycja komentarza
const handleCommentEdit = async (req, res) => {
    if (!req.user) return res.redirect('/login');
    try {
        const commentId = parseInt(req.params.id);

        // Sanityzacja edytowanej treści
        const cleanContent = sanitizeHtml(req.body.content || '', {
            allowedTags: ['b', 'i', 'em', 'strong', 'a'],
            allowedAttributes: { 'a': ['href'] }
        }).trim();

        if (!cleanContent) {
            return res.redirect('back');
        }

        const comment = await prisma.comment.findUnique({ where: { id: commentId } });
        if (!comment || comment.userId !== req.user.id) {
            return res.status(403).send('Brak uprawnień do edycji tego komentarza.');
        }

        await prisma.comment.update({
            where: { id: commentId },
            data: { content: cleanContent, isEdited: true }
        });

        res.redirect('back');
    } catch (err) {
        console.error(err);
        res.redirect('back');
    }
};

app.post('/comments/:id/edit', handleCommentEdit);
app.put('/comments/:id', handleCommentEdit);

// Uniwersalna obsługa usuwania komentarza i odpowiedzi (dla DELETE, POST /comments/:id oraz POST /comments/:id/delete)
const handleCommentDelete = async (req, res) => {
    if (!req.user) return res.redirect('/login');
    try {
        const commentId = parseInt(req.params.id);
        const comment = await prisma.comment.findUnique({ 
            where: { id: commentId }
        });

        if (!comment || comment.userId !== req.user.id) {
            return res.status(403).send('Brak uprawnień do usunięcia tego komentarza.');
        }

        await prisma.comment.delete({ 
            where: { id: commentId } 
        });

        res.redirect('back');
    } catch (err) {
        console.error('Błąd podczas usuwania komentarza:', err);
        res.redirect('back');
    }
};

app.delete('/comments/:id', handleCommentDelete);
app.post('/comments/:id', handleCommentDelete);
app.post('/comments/:id/delete', handleCommentDelete);

// ==========================================
// 2FA - GOOGLE AUTHENTICATOR (TOTP)
// ==========================================
app.get('/auth/2fa/setup', async (req, res) => {
    try {
        const token = req.cookies.token;
        if (!token) return res.redirect('/login');

        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await prisma.user.findUnique({ where: { id: decoded.userId } });
        if (!user) return res.redirect('/login');

        const secret = authenticator.generateSecret();

        await prisma.user.update({
            where: { id: user.id },
            data: { twoFactorSecret: secret }
        });
        const otpauth = typeof authenticator.keyURI === 'function'
            ? authenticator.keyURI(user.email, 'FilmwebClone', secret)
            : `otpauth://totp/FilmwebClone:${encodeURIComponent(user.email)}?secret=${secret}&issuer=FilmwebClone`;
        const qrCodeUrl = await QRCode.toDataURL(otpauth);

        res.render('setup-2fa', { qrCodeUrl, error: null });
    } catch (err) {
        console.error('Błąd konfiguracji 2FA:', err);
        res.redirect('/');
    }
});

app.post('/auth/2fa/enable', async (req, res) => {
    try {
        const token = req.cookies.token;
        if (!token) return res.redirect('/login');

        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await prisma.user.findUnique({ where: { id: decoded.userId } });
        const userCode = (req.body.token || '').trim();

        const isValid = await authenticator.verify({
            token: userCode,
            secret: user.twoFactorSecret
        });

        if (!isValid) {
            const otpauth = typeof authenticator.keyURI === 'function'
                ? authenticator.keyURI(user.email, 'FilmwebClone', user.twoFactorSecret)
                : `otpauth://totp/FilmwebClone:${encodeURIComponent(user.email)}?secret=${user.twoFactorSecret}&issuer=FilmwebClone`;
            const qrCodeUrl = await QRCode.toDataURL(otpauth);
            return res.render('setup-2fa', { qrCodeUrl, error: 'Nieprawidłowy kod z aplikacji. Spróbuj ponownie.' });
        }

        await prisma.user.update({
            where: { id: user.id },
            data: { isTwoFactorEnabled: true }
        });

        res.redirect('/');
    } catch (err) {
        console.error('Błąd włączania 2FA:', err);
        res.redirect('/auth/2fa/setup');
    }
});

app.get('/auth/2fa/verify', (req, res) => {
    const pending = req.cookies.pending_2fa;
    if (!pending) return res.redirect('/login');
    res.render('verify-2fa', { error: null });
});

app.post('/auth/2fa/verify', async (req, res) => {
    try {
        const pending = req.cookies.pending_2fa;
        if (!pending) return res.redirect('/login');

        const decoded = jwt.verify(pending, JWT_SECRET);
        const user = await prisma.user.findUnique({ where: { id: decoded.userId } });

        if (!user || !user.twoFactorSecret) {
            res.clearCookie('pending_2fa');
            return res.redirect('/login');
        }

        const userCode = String(req.body.token || '').trim();
        let isValid = false;
        try {
            const result = await authenticator.verify({
                token: userCode,
                secret: user.twoFactorSecret
            });

            if (typeof result === 'object' && result !== null && 'valid' in result) {
                isValid = Boolean(result.valid);
            } else {
                isValid = Boolean(result);
            }
        } catch (e) {
            isValid = false;
        }

        if (!isValid) {
            return res.render('verify-2fa', { error: 'Nieprawidłowy kod 2FA. Spróbuj ponownie.' });
        }

        res.clearCookie('pending_2fa');

        const fullToken = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '10m' });
        res.cookie('token', fullToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 10 * 60 * 1000
        });

        return res.redirect('/');
    } catch (err) {
        console.error('Błąd 2FA verify:', err);
        res.clearCookie('pending_2fa');
        return res.redirect('/login');
    }
});

app.post('/auth/2fa/disable', async (req, res) => {
    try {
        const token = req.cookies.token;
        if (!token) return res.redirect('/login');

        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await prisma.user.findUnique({ where: { id: decoded.userId } });
        if (!user) return res.redirect('/login');

        const { currentPassword } = req.body;
        if (!currentPassword) {
            return res.render('userMenu', { 
                user, 
                error: 'Podaj aktualne hasło, aby wyłączyć 2FA.', 
                success: null 
            });
        }

        const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
        if (!isPasswordValid) {
            return res.render('userMenu', { 
                user, 
                error: 'Nieprawidłowe hasło. 2FA nie zostało wyłączone.', 
                success: null 
            });
        }

        const updatedUser = await prisma.user.update({
            where: { id: user.id },
            data: {
                isTwoFactorEnabled: false,
                twoFactorSecret: null
            }
        });

        return res.render('userMenu', { 
            user: updatedUser, 
            error: null, 
            success: 'Uwierzytelnianie dwuskładnikowe (2FA) zostało pomyślnie wyłączone.' 
        });
    } catch (err) {
        console.error('Błąd podczas wyłączania 2FA:', err);
        res.redirect('/user/menu');
    }
});

// Uruchomienie serwera
if (process.env.NODE_ENV !== 'test') {
    app.listen(PORT, () => {
        console.log(`Serwer FilmwebClone działa na porcie ${PORT}`);
    });
}

module.exports = app;
