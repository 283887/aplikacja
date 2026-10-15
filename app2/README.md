
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
|   ├── prisma/
|   |   ├── schema.prisma
│   └── server.js         # Główny punkt wejścia aplikacji
│
├── .env                  # Zmienne środowiskowe (baza, sekret JWT)
├── package.json
├── Dockerfile
├── docker-compose.yml
└── README.md
````

### How to run app:
1. make sure that your repositories are updated: sudo apt update
2. install docker: sudo apt install -y docker.io
3. start docker: sudo systemctl start docker
4. [optional] enable docker: sudo systemctl enable docker
5. download repository: git clone https://github.com/283887/aplikacja.git
6. change directory to aplikacja/app2
7. run app: sudo docker compose up --build
8. app runs on localhost port 3000 :) 
