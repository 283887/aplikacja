const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Konfiguracja widoków EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// Tymczasowa trasa główna (żeby sprawdzić czy działa)
app.get('/', (req, res) => {
    res.render('index', { user: null, movies: [] });
});

app.get('/login', (req, res) => {
    res.render('login', { error: null, success: null });
});

// Uruchomienie serwera
app.listen(PORT, () => {
    console.log(`Serwer działa na porcie ${PORT}`);
});
