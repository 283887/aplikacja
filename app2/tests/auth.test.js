const request = require('supertest');
const app = require('../src/server');

describe('Zadanie 3: Testy automatyczne modułu uwierzytelniania', () => {
  const unique = Date.now();
  const validUser = {
    username: `user${unique}`,
    email: `test${unique}@pwr.edu.pl`,
    password: 'Password123'
  };

  describe('1. Rejestracja (POST /auth/register)', () => {
    it('powinien odrzucić rejestrację przy braku wymaganych pól', async () => {
      const res = await request(app)
        .post('/auth/register')
        .type('form')
        .send({
          username: '',
          email: '',
          password: ''
        });

      expect([200, 400]).toContain(res.statusCode);
      expect(res.text).toMatch(/Wszystkie pola są wymagane/i);
    });

    it('powinien zablokować rejestrację ze zbyt słabym hasłem (wymóg bezpieczeństwa)', async () => {
      const res = await request(app)
        .post('/auth/register')
        .type('form')
        .send({
          username: `weak${unique}`,
          email: `weak${unique}@pwr.edu.pl`,
          password: '123'
        });

      expect([200, 400]).toContain(res.statusCode);
      expect(res.text).toMatch(/Hasło musi mieć co najmniej 8 znaków/i);
    });

    it('powinien zablokować rejestrację z niedozwolonymi znakami w loginie', async () => {
      const res = await request(app)
        .post('/auth/register')
        .type('form')
        .send({
          username: 'user!@#$',
          email: `invalid${unique}@pwr.edu.pl`,
          password: 'Password123'
        });

      expect([200, 400]).toContain(res.statusCode);
      expect(res.text).toMatch(/wyłącznie litery i cyfry/i);
    });

    it('powinien poprawnie zarejestrować nowego użytkownika spełniającego kryteria', async () => {
      const res = await request(app)
        .post('/auth/register')
        .type('form')
        .send(validUser);

      expect([200, 201, 302]).toContain(res.statusCode);
    });

    it('powinien zablokować próbę rejestracji duplikatu (ten sam login/email)', async () => {
      const res = await request(app)
        .post('/auth/register')
        .type('form')
        .send(validUser);

      expect([200, 400, 409]).toContain(res.statusCode);
      expect(res.text).toMatch(/istnieje/i);
    });
  });

  describe('2. Logowanie (POST /auth/login)', () => {
    it('powinien odrzucić logowanie nieistniejącego użytkownika', async () => {
      const res = await request(app)
        .post('/auth/login')
        .type('form')
        .send({
          identifier: `nonexistent${unique}@pwr.edu.pl`,
          password: 'Password123'
        });

      expect([200, 400, 401]).toContain(res.statusCode);
      expect(res.text).toMatch(/Nieprawidłowy login lub hasło/i);
    });

    it('powinien odrzucić logowanie z błędnym hasłem i zwrócić bezpieczny komunikat', async () => {
      const res = await request(app)
        .post('/auth/login')
        .type('form')
        .send({
          identifier: validUser.email,
          password: 'ZleHaslo123'
        });

      expect([200, 400, 401]).toContain(res.statusCode);
      expect(res.text).toMatch(/Nieprawidłowy login lub hasło/i);
    });

    it('powinien zalogować poprawnego użytkownika i nadać ciasteczko sesyjne HttpOnly', async () => {
      const res = await request(app)
        .post('/auth/login')
        .type('form')
        .send({
          identifier: validUser.email,
          password: validUser.password
        });

      expect([200, 302]).toContain(res.statusCode);

      const cookies = res.headers['set-cookie'];
      expect(cookies).toBeDefined();
      const tokenCookie = cookies.find(c => c.startsWith('token='));
      expect(tokenCookie).toBeDefined();
      expect(tokenCookie).toContain('HttpOnly');
    });
  });
});
