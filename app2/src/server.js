const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');

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
        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.render('login', { error: 'Wszystkie pola są wymagane!', success: null });
        }

        // Sprawdzanie czy użytkownik już istnieje
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

// Uruchomienie serwera
app.listen(PORT, () => {
    console.log(`Serwer FilmwebClone działa na porcie ${PORT}`);
});
