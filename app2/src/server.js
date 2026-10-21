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

// --- POMOCNICZY MIDDLEWARE: Sprawdzanie zalogowanego użytkownika z ciasteczka ---
const checkAuth = async (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        req.user = null;
        return next();
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        // Pobieramy aktualne dane użytkownika z bazy
        const user = await prisma.user.findUnique({ where: { id: decoded.userId } });
        req.user = user || null;
    } catch (err) {
        req.user = null; // Token wygasł lub jest niepoprawny
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
            },
            include: { reviews: true }
        });

        // Obliczanie średniej ocen dla filmów
        const moviesWithRatings = movies.map(movie => {
            const sum = movie.reviews.reduce((acc, r) => acc + r.rating, 0);
            const averageRating = movie.reviews.length > 0 ? sum / movie.reviews.length : null;
            return { ...movie, averageRating };
        });

        res.render('index', { user: req.user, movies: moviesWithRatings, searchTerm: search });
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

        // 1. Walidacja obecności pól
        if (!username || !email || !password) {
            return res.render('login', { error: 'Wszystkie pola są wymagane!', success: null });
        }

        // 2. Walidacja formatu e-mail
        if (!validator.isEmail(email)) {
            return res.render('login', { error: 'Podaj poprawny adres e-mail (np. user@domena.pl).', success: null });
        }

        // 3. Walidacja loginu (alfanumeryczny, 3-25 znaków)
        if (!validator.isAlphanumeric(username, 'pl-PL') || username.length < 3 || username.length > 25) {
            return res.render('login', { 
                error: 'Nazwa użytkownika musi mieć od 3 do 25 znaków i zawierać wyłącznie litery i cyfry.', 
                success: null 
            });
        }

        // 4. Walidacja siły hasła (min. 8 znaków, wielka litera, cyfra)
        const passwordPolicy = { minLength: 8, minUppercase: 1, minNumbers: 1, minSymbols: 0 };
        if (!validator.isStrongPassword(password, passwordPolicy)) {
            return res.render('login', { 
                error: 'Hasło musi mieć co najmniej 8 znaków, zawierać przynajmniej jedną wielką literę i jedną cyfrę.', 
                success: null 
            });
        }

        // Sprawdzanie unikalności
        const existingUser = await prisma.user.findFirst({
            where: { OR: [{ email }, { username }] }
        });

        if (existingUser) {
            return res.render('login', { error: 'Użytkownik o takim e-mailu lub nazwie już istnieje.', success: null });
        }

        // Haszowanie hasła (Bcrypt)
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

// 4. Obsługa Logowania (Ciasteczka ważne 10 minut)
app.post('/auth/login', async (req, res) => {
    try {
        const { identifier, password } = req.body; // identifier to email lub username

        const user = await prisma.user.findFirst({
            where: { OR: [{ email: identifier }, { username: identifier }] }
        });

        if (!user) {
            return res.render('login', { error: 'Nieprawidłowy login lub hasło.', success: null });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.render('login', { error: 'Nieprawidłowy login lub hasło.', success: null });
        }
	// --- OBSŁUGA 2FA (TOTP) ---
        if (user.isTwoFactorEnabled) {
            // CZYŚCIMY stary token sesyjny, aby użytkownik NIE był zalogowany przed podaniem kodu 2FA!
            res.clearCookie('token');

            // Tymczasowy token na czas weryfikacji 6-cyfrowego kodu (ważny 5 minut)
            const pendingToken = jwt.sign({ userId: user.id, is2faPending: true }, JWT_SECRET, { expiresIn: '5m' });
            res.cookie('pending_2fa', pendingToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'lax',
                maxAge: 5 * 60 * 1000
            });
            return res.redirect('/auth/2fa/verify');
        }
        // --------------------------


        // Tworzenie tokena JWT (ważność 10 minut)
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '10m' });

        // Zapisanie tokena w bezpiecznym ciasteczku (HttpOnly, ważne 10 minut)
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
	    sameSite: 'lax',
            maxAge: 10 * 60 * 1000 // 10 minut w ms
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

// Trasy resetowania hasła (Zadanie dodatkowe)

// Przekierowanie po wklejeniu tokenu z formularza
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
        const resetTokenExpiry = new Date(Date.now() + 15 * 60 * 1000); // 15 minut ważności

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


// 6. Menu użytkownika (Dostępne tylko dla zalogowanych)
app.get('/user/menu', (req, res) => {
    if (!req.user) return res.redirect('/login');
    res.render('userMenu', { user: req.user, error: null, success: null });
});

// 7. Usuwanie konta użytkownika (Tylko dla zalogowanych)
app.post('/user/delete', async (req, res) => {
    if (!req.user) return res.redirect('/login');
    try {
        // Usuwamy recenzje przypisane do użytkownika
        await prisma.review.deleteMany({
            where: { userId: req.user.id }
        });

        // Usuwamy użytkownika z bazy
        await prisma.user.delete({
            where: { id: req.user.id }
        });

        // Czyszczenie ciasteczka po usunięciu konta
        res.clearCookie('token');
        res.redirect('/');
    } catch (err) {
        console.error(err);
        res.redirect('/user/menu');
    }
});

// 8. Szczegóły filmu i dodawanie recenzji
app.get('/movies/:id', async (req, res) => {
    try {
        const movieId = parseInt(req.params.id);
        const movie = await prisma.movie.findUnique({
            where: { id: movieId },
            include: {
                reviews: {
                    include: { user: true },
                    orderBy: { createdAt: 'desc' }
                }
            }
        });

        if (!movie) return res.status(404).send("Film nie został znaleziony");

        const sum = movie.reviews.reduce((acc, r) => acc + r.rating, 0);
        const averageRating = movie.reviews.length > 0 ? sum / movie.reviews.length : null;

        res.render('movie', { user: req.user, movie: { ...movie, averageRating }, error: null, success: null });
    } catch (err) {
        console.error(err);
        res.status(500).send("Błąd serwera");
    }
});

// 9. Dodawanie recenzji (Tylko dla zalogowanych)
app.post('/movies/:id/review', async (req, res) => {
    if (!req.user) return res.redirect('/login');
    try {
        const movieId = parseInt(req.params.id);
        const { rating, comment } = req.body;

        await prisma.review.create({
            data: {
                rating: parseInt(rating),
                comment,
                userId: req.user.id,
                movieId: movieId
            }
        });

        res.redirect(`/movies/${movieId}`);
    } catch (err) {
        console.error(err);
        res.redirect('/');
    }
});

// ==========================================
// 2FA - GOOGLE AUTHENTICATOR (TOTP)
// ==========================================

// 1. Ekran konfiguracji 2FA i generowanie QR Code (dostępny po zalogowaniu)
app.get('/auth/2fa/setup', async (req, res) => {
    try {
        const token = req.cookies.token;
        if (!token) return res.redirect('/login');

        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await prisma.user.findUnique({ where: { id: decoded.userId } });
        if (!user) return res.redirect('/login');

        // Generujemy nowy unikalny sekret Base32
        const secret = authenticator.generateSecret();

        // Zapisujemy tymczasowo wygenerowany sekret w bazie
        await prisma.user.update({
            where: { id: user.id },
            data: { twoFactorSecret: secret }
        });
	const otpauth = typeof authenticator.keyURI === 'function'
	    ? authenticator.keyURI(user.email, 'FilmwebClone', secret)
	    : `otpauth://totp/FilmwebClone:${encodeURIComponent(user.email)}?secret=${secret}&issuer=FilmwebClone`
        const qrCodeUrl = await QRCode.toDataURL(otpauth);

        res.render('setup-2fa', { qrCodeUrl, error: null });
    } catch (err) {
        console.error('Błąd konfiguracji 2FA:', err);
        res.redirect('/');
    }
});

// 2. Aktywacja 2FA - weryfikacja pierwszego kodu z aplikacji
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

        // Aktywujemy 2FA dla konta
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

// 3. Widok weryfikacji 2FA podczas logowania
app.get('/auth/2fa/verify', (req, res) => {
    const pending = req.cookies.pending_2fa;
    if (!pending) return res.redirect('/login');
    res.render('verify-2fa', { error: null });
});

// 4. Zatwierdzenie kodu 2FA i pełne zalogowanie
app.post('/auth/2fa/verify', async (req, res) => {
    console.log('--- [2FA DEBUG START] ---');
    console.log('Otrzymano żądanie POST /auth/2fa/verify');
    console.log('req.body:', req.body);
    console.log('req.cookies:', req.cookies);

    try {
        const pending = req.cookies.pending_2fa;
        if (!pending) {
            console.log('[2FA DEBUG] Brak ciasteczka pending_2fa -> redirect /login');
            return res.redirect('/login');
        }

        const decoded = jwt.verify(pending, JWT_SECRET);
        console.log('[2FA DEBUG] Zdekodowany pending token:', decoded);

        const user = await prisma.user.findUnique({ where: { id: decoded.userId } });
        console.log('[2FA DEBUG] Użytkownik z bazy:', user ? { id: user.id, email: user.email, hasSecret: !!user.twoFactorSecret, is2fa: user.isTwoFactorEnabled } : null);

        if (!user || !user.twoFactorSecret) {
            console.log('[2FA DEBUG] Brak użytkownika lub brak twoFactorSecret w bazie!');
            res.clearCookie('pending_2fa');
            return res.redirect('/login');
        }

        const userCode = String(req.body.token || '').trim();
        console.log('[2FA DEBUG] Kod wpisany przez użytkownika:', userCode);
        console.log('[2FA DEBUG] Sekret w bazie:', user.twoFactorSecret);

        let isValid = false;
        try {
            const result = await authenticator.verify({
                token: userCode,
                secret: user.twoFactorSecret
            });

            // Jeśli zwrócono obiekt { valid: true/false }, bierzemy result.valid;
            // w przeciwnym razie bierzemy samą wartość result (boolean)
            if (typeof result === 'object' && result !== null && 'valid' in result) {
                isValid = Boolean(result.valid);
            } else {
                isValid = Boolean(result);
            }

            console.log('[2FA DEBUG] Przetworzony wynik isValid (boolean):', isValid);
        } catch (e) {
            console.log('[2FA DEBUG] authenticator.verify rzucił błąd:', e.message);
            isValid = false;
        }

        if (!isValid) {
            console.log('[2FA DEBUG] Kod NIEPRAWIDŁOWY. Blokuję dostęp.');
            return res.render('verify-2fa', { error: 'Nieprawidłowy kod 2FA. Spróbuj ponownie.' });
        }

        if (!isValid) {
            console.log('[2FA DEBUG] Kod NIEPRAWIDŁOWY. Wywołuję res.render(verify-2fa)');
            return res.render('verify-2fa', { error: 'Nieprawidłowy kod 2FA. Spróbuj ponownie.' });
        }

        console.log('[2FA DEBUG] Kod PRAWIDŁOWY. Ustawiam token sesyjny.');
        res.clearCookie('pending_2fa');

        const fullToken = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '10m' });
        res.cookie('token', fullToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 10 * 60 * 1000
        });

        console.log('[2FA DEBUG] Przekierowuję na /');
        return res.redirect('/');
    } catch (err) {
        console.error('[2FA DEBUG] Błąd w głównym bloku catch:', err);
        res.clearCookie('pending_2fa');
        return res.redirect('/login');
    }
});

// 5. Wyłączenie 2FA (wymaga potwierdzenia hasłem)
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

        // Weryfikacja hasła użytkownika przed wyłączeniem 2FA
        const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
        if (!isPasswordValid) {
            return res.render('userMenu', { 
                user, 
                error: 'Nieprawidłowe hasło. 2FA nie zostało wyłączone.', 
                success: null 
            });
        }

        // Czyszczenie flagi oraz sekretu w bazie danych
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

// Uruchomienie serwera (tylko poza środowiskiem testowym)
if (process.env.NODE_ENV !== 'test') {
    app.listen(PORT, () => {
        console.log(`Serwer FilmwebClone działa na porcie ${PORT}`);
    });
}

module.exports = app;
