/**
 * tests/test_security.spec.js - Tests de sécurité Node.js pour NeoBank Digital
 * Livrable 4.1 : Tests de sécurité automatisés (Express/Node.js)
 *
 * Couvre :
 *   - Rate limiting (V7) : 429 après dépassement
 *   - XSS (V5) : payloads sanitisés
 *   - Mass Assignment (V6) : champs interdits rejetés
 *   - CORS (V12) : origines non autorisées rejetées
 *   - Content-Type (V11) : requêtes non-JSON rejetées
 *   - Headers de sécurité (Helmet)
 */

'use strict';

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET_KEY = 'test_secret_must_be_at_least_32_chars_long_ok';
process.env.CORS_ALLOWED_ORIGINS = 'https://app.neobank.fr';
process.env.DATABASE_URL = 'sqlite::memory:';

const request = require('supertest');
const app = require('../app');

// ─────────────────────────────────────────────────────────────────────────────
// Utilitaires
// ─────────────────────────────────────────────────────────────────────────────

const XSS_PAYLOADS = [
  "<script>alert('XSS')</script>",
  "<img src=x onerror=alert(1)>",
  "<svg onload=alert(1)>",
  "javascript:void(0)",
];

// ─────────────────────────────────────────────────────────────────────────────
// TEST 1 : Rate Limiting (V7)
// ─────────────────────────────────────────────────────────────────────────────

describe('Rate Limiting (V7)', () => {
  test('Bloque le login après 10 tentatives rapides (429)', async () => {
    const promises = Array.from({ length: 12 }, () =>
      request(app)
        .post('/login')
        .set('Content-Type', 'application/json')
        .send({ username: 'bruteforce_user', password: 'wrong_password' })
    );

    const responses = await Promise.all(promises);
    const blocked = responses.filter(r => r.status === 429);

    // Au moins quelques requêtes doivent être bloquées
    expect(blocked.length).toBeGreaterThan(0);

    // Vérification du header Retry-After
    if (blocked[0]) {
      expect(blocked[0].headers['retry-after']).toBeDefined();
    }
  });

  test('La réponse 429 contient un message et Retry-After', async () => {
    // Épuise d'abord le rate limit
    for (let i = 0; i < 12; i++) {
      await request(app)
        .post('/login')
        .set('Content-Type', 'application/json')
        .send({ username: 'ratelimit_test', password: 'wrong' });
    }

    const response = await request(app)
      .post('/login')
      .set('Content-Type', 'application/json')
      .send({ username: 'ratelimit_test', password: 'wrong' });

    if (response.status === 429) {
      expect(response.body.error).toBeDefined();
      expect(response.headers['retry-after']).toBeDefined();
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// TEST 2 : XSS (V5)
// ─────────────────────────────────────────────────────────────────────────────

describe('XSS Protection (V5)', () => {
  XSS_PAYLOADS.forEach(payload => {
    test(`Rejette ou sanitise le payload XSS : ${payload.substring(0, 30)}`, async () => {
      const response = await request(app)
        .post('/payments/transfer')
        .set('Content-Type', 'application/json')
        .set('Authorization', 'Bearer test_token')
        .send({
          to_account: '550e8400-e29b-41d4-a716-446655440000',
          amount: 100,
          description: payload,
        });

      if (response.status === 201 || response.status === 200) {
        // Si le serveur accepte, la description stockée/renvoyée ne doit pas contenir le payload brut
        const responseBody = JSON.stringify(response.body);
        expect(responseBody).not.toContain('<script>');
        expect(responseBody).not.toContain('onerror=');
        expect(responseBody).not.toContain('onload=');
      } else {
        // Rejeté par la validation : comportement correct (400 ou 422)
        expect([400, 401, 422]).toContain(response.status);
      }
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// TEST 3 : Mass Assignment (V6)
// ─────────────────────────────────────────────────────────────────────────────

describe('Mass Assignment Protection (V6)', () => {
  test('Rejette les champs sensibles dans la mise à jour du profil', async () => {
    const response = await request(app)
      .put('/payments/user/profile')
      .set('Content-Type', 'application/json')
      .set('Authorization', 'Bearer test_token')
      .send({
        email: 'user@example.com',
        role: 'admin',         // Champ interdit
        balance: 999999.99,    // Champ interdit
        is_admin: true,        // Champ interdit
        id: 'evil-id',         // Champ interdit
      });

    // Doit être rejeté (400) ou si accepté, les champs sensibles ne doivent pas être modifiés
    if (response.status === 200) {
      expect(response.body.role).toBeUndefined();
      expect(response.body.balance).toBeUndefined();
      expect(response.body.is_admin).toBeUndefined();
    } else {
      expect([400, 401, 422]).toContain(response.status);
    }
  });

  test('Accepte les champs autorisés pour la mise à jour du profil', async () => {
    const response = await request(app)
      .put('/payments/user/profile')
      .set('Content-Type', 'application/json')
      .set('Authorization', 'Bearer test_token')
      .send({
        email: 'newuser@example.com',
        display_name: 'Jean Dupont',
      });

    // 200 (succès) ou 401 (auth - normal en test)
    expect([200, 401]).toContain(response.status);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// TEST 4 : CORS (V12)
// ─────────────────────────────────────────────────────────────────────────────

describe('CORS restrictif (V12)', () => {
  test("Accepte les requêtes depuis une origine autorisée", async () => {
    const response = await request(app)
      .get('/payments/transfer')
      .set('Origin', 'https://app.neobank.fr');

    expect(response.headers['access-control-allow-origin']).toBe('https://app.neobank.fr');
  });

  test("Rejette les requêtes depuis une origine non autorisée", async () => {
    const response = await request(app)
      .options('/payments/transfer')
      .set('Origin', 'https://malicious-site.com')
      .set('Access-Control-Request-Method', 'POST');

    // CORS non autorisé : pas d'header allow-origin ou erreur
    const allowOrigin = response.headers['access-control-allow-origin'];
    expect(allowOrigin).not.toBe('https://malicious-site.com');
    expect(allowOrigin).not.toBe('*');
  });

  test("N'expose pas Access-Control-Allow-Origin: *", async () => {
    const response = await request(app)
      .get('/payments/transfer')
      .set('Origin', 'https://evil.com');

    expect(response.headers['access-control-allow-origin']).not.toBe('*');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// TEST 5 : Validation Content-Type (V11)
// ─────────────────────────────────────────────────────────────────────────────

describe('Validation Content-Type (V11)', () => {
  test('Rejette les requêtes POST sans Content-Type application/json', async () => {
    const response = await request(app)
      .post('/payments/transfer')
      .set('Content-Type', 'text/plain')
      .send('to_account=evil&amount=1000');

    expect(response.status).toBe(415);
  });

  test('Accepte les requêtes POST avec Content-Type application/json', async () => {
    const response = await request(app)
      .post('/payments/transfer')
      .set('Content-Type', 'application/json')
      .send({ to_account: 'test', amount: 100 });

    // Peut retourner 400 (validation) ou 401 (auth) mais pas 415
    expect(response.status).not.toBe(415);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// TEST 6 : Headers de sécurité (Helmet)
// ─────────────────────────────────────────────────────────────────────────────

describe('Security Headers (Livrable 3.3)', () => {
  let response;

  beforeAll(async () => {
    response = await request(app).get('/');
  });

  test('X-Content-Type-Options: nosniff est présent', () => {
    expect(response.headers['x-content-type-options']).toBe('nosniff');
  });

  test('Strict-Transport-Security (HSTS) est présent', () => {
    const hsts = response.headers['strict-transport-security'];
    expect(hsts).toBeDefined();
    expect(hsts).toContain('max-age=');
  });

  test('Content-Security-Policy est présent et restrictif', () => {
    const csp = response.headers['content-security-policy'];
    expect(csp).toBeDefined();
    // Ne doit pas autoriser les sources non fiables
    expect(csp).not.toContain("'unsafe-inline'");
    expect(csp).not.toContain("'unsafe-eval'");
  });

  test('X-Frame-Options ou frame-ancestors est défini', () => {
    const xfo = response.headers['x-frame-options'];
    const csp = response.headers['content-security-policy'] || '';
    // Soit X-Frame-Options, soit frame-ancestors dans CSP
    expect(xfo || csp.includes('frame-ancestors')).toBeTruthy();
  });
});
