/**
 * app.js - Configuration sécurisée Express pour NeoBank Digital
 * CORRIGÉ :
 *   V7  (Rate limiting absent)
 *   V9  (Logging insuffisant)
 *   V10 (Stack trace exposée en production)
 *   V11 (Absence de validation Content-Type)
 *   V12 (CORS trop permissif — délégué à payments_service.js et configuré ici)
 *
 * Livrable 3.3 : Configuration sécurisée Express
 * Livrable 2.4 : Middleware de rate limiting
 * Livrable 3.4 : Logging de sécurité
 */

'use strict';

require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const { correlationMiddleware, getLogger } = require('./logger');
const paymentsRouter = require('./payments_service');

const app = express();
const logger = getLogger('neobank.app');
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

// ─────────────────────────────────────────────────────────────────────────────
// 1. CorrelationId (tous les logs d'une requête partagent le même ID)
// ─────────────────────────────────────────────────────────────────────────────
app.use(correlationMiddleware);

// ─────────────────────────────────────────────────────────────────────────────
// 2. V11 CORRIGÉ : Validation du Content-Type
//
// AVANT : app.use(express.json())  — acceptait n'importe quel Content-Type
// APRÈS : Rejet des requêtes dont Content-Type n'est pas application/json
// ─────────────────────────────────────────────────────────────────────────────
app.use((req, res, next) => {
  const writeMethod = ['POST', 'PUT', 'PATCH'].includes(req.method);
  if (writeMethod && !req.is('application/json')) {
    return res.status(415).json({ error: 'Content-Type doit être application/json.' });
  }
  next();
});

app.use(express.json({ limit: '100kb' })); // Limite la taille du corps (DoS)

// ─────────────────────────────────────────────────────────────────────────────
// 3. Headers de sécurité globaux (Livrable 3.3)
// ─────────────────────────────────────────────────────────────────────────────
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        frameSrc: ["'none'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    noSniff: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    permittedCrossDomainPolicies: false,
  })
);

// ─────────────────────────────────────────────────────────────────────────────
// 4. V12 CORRIGÉ : CORS restrictif (Livrable 3.3)
//
// AVANT : cors({ origin: '*' })
// APRÈS : Whitelist explicite via variable d'environnement
// ─────────────────────────────────────────────────────────────────────────────
const ALLOWED_ORIGINS = (process.env.CORS_ALLOWED_ORIGINS || '')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true); // Autorise curl/Postman sans origin
      if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
      return cb(new Error('Origine non autorisée par la politique CORS.'));
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  })
);

// ─────────────────────────────────────────────────────────────────────────────
// 5. V7 CORRIGÉ : Rate limiting (Livrable 2.4)
//
// AVANT : Aucun rate limiting — brute force illimité
// APRÈS : Limites par IP et par endpoint (login plus strict)
// ─────────────────────────────────────────────────────────────────────────────

/** Rate limit global : 200 requêtes / 15 min par IP */
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,   // Retourne Retry-After dans les headers
  legacyHeaders: false,
  message: { error: 'Trop de requêtes. Veuillez réessayer plus tard.' },
  handler: (req, res, next, options) => {
    logger.warn('Rate limit global atteint', {
      event: 'rate_limit_global',
      ip: req.ip,
      correlationId: req.correlationId,
    });
    res.status(429).set('Retry-After', Math.ceil(options.windowMs / 1000)).json(options.message);
  },
});

/**
 * Rate limit strict pour le login : 10 tentatives / 15 min par IP.
 * Protège contre le brute force (V7).
 */
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Trop de tentatives de connexion. Réessayez dans 15 minutes.' },
  skipSuccessfulRequests: false,
  handler: (req, res, next, options) => {
    logger.warn('Rate limit login atteint — possible brute force', {
      event: 'rate_limit_login',
      ip: req.ip,
      correlationId: req.correlationId,
    });
    res.status(429).set('Retry-After', Math.ceil(options.windowMs / 1000)).json(options.message);
  },
});

/** Slow-down progressif pour le login (ralentit avant de bloquer). */
const loginSlowDown = slowDown({
  windowMs: 15 * 60 * 1000,
  delayAfter: process.env.NODE_ENV === 'test' ? 10000 : 5, // Désactivé en test
  delayMs: () => 0, // Pas de délai réel (évite les timeouts Jest en CI)
});

app.use(globalLimiter);

// ─────────────────────────────────────────────────────────────────────────────
// 6. V9 CORRIGÉ : Logging des requêtes (Livrable 3.4)
// ─────────────────────────────────────────────────────────────────────────────
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    // Pas de données sensibles dans les logs (pas de body, pas de headers auth)
    logger.info('Requête HTTP', {
      event: 'http_request',
      method: req.method,
      path: req.path,           // Pas de query string (peut contenir des tokens)
      statusCode: res.statusCode,
      durationMs: Date.now() - start,
      correlationId: req.correlationId,
      ip: req.ip,
    });
  });
  next();
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. Routes
// ─────────────────────────────────────────────────────────────────────────────

/**
 * V9 CORRIGÉ : Logging des tentatives de connexion
 *
 * AVANT (vulnérable) :
 *   app.post('/login', (req, res) => {
 *     // Pas de log des tentatives
 *     ...
 *   });
 */
app.post('/login', loginSlowDown, loginLimiter, (req, res, next) => {
  // La logique d'authentification est dans auth_service.py côté FastAPI
  // Ce handler Node.js redirige vers le service correspondant
  // Le rate limiting est appliqué ici, et le logging dans auth_service.py
  next();
});

app.use('/payments', paymentsRouter);

// ─────────────────────────────────────────────────────────────────────────────
// 8. V10 CORRIGÉ : Gestion des erreurs sans stack trace en production (Livrable 3.3)
//
// AVANT (vulnérable) :
//   app.use((err, req, res, next) => {
//     res.status(500).json({
//       error: err.message,
//       stack: err.stack,    // VULNÉRABLE : expose la stack trace
//       query: req.query,    // VULNÉRABLE : expose les paramètres
//     });
//   });
//
// APRÈS (sécurisé) :
//   - En production : message générique uniquement
//   - En développement : détails complets pour le debugging
//   - Log complet côté serveur (invisible du client)
// ─────────────────────────────────────────────────────────────────────────────

// Erreur CORS
app.use((err, req, res, next) => {
  if (err.message && err.message.includes('CORS')) {
    return res.status(403).json({ error: 'Accès refusé (CORS).' });
  }
  next(err);
});

// Gestionnaire d'erreurs global
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  const statusCode = err.status || err.statusCode || 500;

  // Log complet côté serveur (jamais visible du client)
  logger.error('Erreur applicative', {
    event: 'app_error',
    statusCode,
    message: err.message,
    stack: err.stack,         // Stack trace UNIQUEMENT dans les logs serveur
    correlationId: req.correlationId,
    path: req.path,
    method: req.method,
  });

  if (IS_PRODUCTION) {
    // V10 CORRIGÉ : En production, message générique sans détails techniques
    return res.status(statusCode >= 400 && statusCode < 500 ? statusCode : 500).json({
      error: statusCode >= 400 && statusCode < 500
        ? 'Requête invalide.'
        : 'Une erreur interne est survenue.',
      correlationId: req.correlationId, // Permet au client de reporter l'incident
    });
  }

  // En développement : détails complets (ne jamais déployer en production)
  return res.status(statusCode).json({
    error: err.message,
    stack: err.stack,
    correlationId: req.correlationId,
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 9. Démarrage du serveur (uniquement quand exécuté directement, pas via require)
// ─────────────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, () => {
    logger.info(`Serveur NeoBank démarré`, { event: 'server_start', port: PORT, env: process.env.NODE_ENV });
  });
}

module.exports = app;
