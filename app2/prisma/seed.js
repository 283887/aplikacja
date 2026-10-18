const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');

const prisma = new PrismaClient();

async function main() {
  // Wyczyszczenie starej bazy danych
  await prisma.review.deleteMany();
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
      description: 'Złodziej, który kradnie korporacyjne seksecrets poprzez technologiczne wchodzenie w snów, otrzymuje zadanie wszczepienia idei.',
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

  // Dodanie przykładowej recenzji
  await prisma.review.create({
    data: {
      rating: 9,
      comment: 'Absolutne arcydzieło kinematografii!',
      userId: user.id,
      movieId: movie1.id,
    },
  });

  console.log('Baza danych została uzupełniona przykładowymi danymi!');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
