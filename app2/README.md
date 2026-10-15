
````text
projekt-filmweb/
│
├── src/
│   ├── config/           # Połączenie z bazą PostgreSQL
│   ├── controllers/      # Logika stron i akcji (auth, movies, reviews)
│   ├── middleware/       # Weryfikacja JWT z ciasteczka (AuthGuard)
│   ├── routes/           # Ścieżki widoków (np. webRoutes.js) oraz API
│   ├── views/            # Widoki HTML (szablony EJS/Handlebars)
│   │   ├── partials/     # Powtarzalne elementy (np. header, footer, wyszukiwarka)
│   │   ├── index.ejs     # Strona główna / startowa
│   │   ├── login.ejs     # Panel logowania / rejestracji
│   │   ├── userMenu.ejs  # Menu użytkownika (edycja profilu)
│   │   └── movie.ejs     # Szczegóły filmu + oceny i komentarze
│   └── server.js         # Główny punkt wejścia aplikacji
│
├── .env                  # Zmienne środowiskowe (baza, sekret JWT)
├── package.json
├── Dockerfile
├── docker-compose.yml
└── README.md
````
