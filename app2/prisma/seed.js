const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');

const prisma = new PrismaClient();

async function main() {
  // Wyczyszczenie bazy danych (najpierw tabele zależne, potem rodzice)
  await prisma.comment.deleteMany();
  await prisma.rating.deleteMany();
  await prisma.movie.deleteMany();
  await prisma.user.deleteMany();

  // Utworzenie przykładowego użytkownika (hasło: "password123")
  const hashedPassword = await bcrypt.hash('password123', 10);
  const user = await prisma.user.create({
    data: {
      username: 'JanKowalski',
      email: 'jan@example.com',
      password: hashedPassword,
    },
  });

  // Utworzenie przykładowych filmów
  const movie1 = await prisma.movie.create({
    data: {
      title: 'Incepcja',
      director: 'Christopher Nolan',
      description: 'Złodziej, który kradnie korporacyjne sekrety poprzez technologiczne wchodzenie w sny, otrzymuje zadanie wszczepienia idei.',
      averageRating: 9.0,
    },
  });

  const movie2 = await prisma.movie.create({
    data: {
      title: 'Skazani na Shawshank',
      director: 'Frank Darabont',
      description: 'Adaptacja opowiadania Stephena Kinga. Bankier zostaje niesłusznie skazany na dożywocie w ciężkim więzieniu.',
      averageRating: 9.5,
    },
  });

  const movie3 = await prisma.movie.create({
    data: {
      title: 'Interstellar',
      director: 'Christopher Nolan',
      description: 'Grupa naukowców odkrywa tunel czasoprzestrzenny, próbując znaleźć nowy dom dla ludzkości.',
      averageRating: 8.8,
    },
  });

  // Dodanie przykładowej oceny (Rating)
  await prisma.rating.create({
    data: {
      value: 9,
      userId: user.id,
      movieId: movie1.id,
    },
  });

  // Dodanie przykładowego komentarza (Comment)
  const comment = await prisma.comment.create({
    data: {
      content: 'Absolutne arcydzieło kinematografii!',
      userId: user.id,
      movieId: movie1.id,
    },
  });

  // Dodanie przykładowej odpowiedzi na komentarz (Reply)
  await prisma.comment.create({
    data: {
      content: 'Zgadzam się w 100%, końcówka jest genialna.',
      userId: user.id,
      movieId: movie1.id,
      parentId: comment.id, // Powiązanie jako odpowiedź do powyższego komentarza
    },
  });

  console.log('Baza danych została pomyślnie uzupełniona nowymi danymi!');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
