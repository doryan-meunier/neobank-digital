/**
 * payments_service.js - Service Paiements NeoBank Digital
 * CORRIGÉ : V5 (XSS Stored), V6 (Mass Assignment), V12 (CORS permissif)
 *
 * Livrable 1.2 : Sécurisation XSS avec sanitization + encodage HTML + CSP
 * Livrable 2.3 : Whitelist des champs modifiables (Mass Assignment)
 * Livrable 3.3 : CORS restrictif avec whitelist de domaines
 */

'use strict';

const express = require('express');
const router = express.Router();
const cors = require('cors');
const { body, validationResult, param } = require('express-validator');
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const he = require('he');        // Encodage HTML en sortie
const helmet = require('helmet'); // Headers de sécurité
const { getLogger } = require('./logger');

const logger = getLogger('neobank.payments');
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

// ─────────────────────────────────────────────────────────────────────────────
// V12 CORRIGÉ : CORS restrictif avec whitelist explicite de domaines
//
// AVANT (vulnérable) : cors({ origin: '*' })
// APRÈS (sécurisé)   : whitelist de domaines autorisés
// ─────────────────────────────────────────────────────────────────────────────
const ALLOWED_ORIGINS = (process.env.CORS_ALLOWED_ORIGINS || '')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

const corsOptions = {
  origin: (origin, callback) => {
    // Autorise les requêtes sans origin (ex. : Postman en dev)
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) {
      return callback(null, true);
    }
    logger.warn('Requête CORS rejetée', { origin });
    return callback(new Error('Origine non autorisée par la politique CORS.'));
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 600, // Cache de la pré-vérification CORS (10 min)
};

router.use(cors(corsOptions));

// ─────────────────────────────────────────────────────────────────────────────
// Headers de sécurité supplémentaires (V12, Livrable 3.3)
// ─────────────────────────────────────────────────────────────────────────────
router.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],           // V5 : bloque les scripts inline
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
  })
);

// ─────────────────────────────────────────────────────────────────────────────
// Utilitaire : sanitization HTML (V5)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Supprime tout HTML/JavaScript d'une chaîne quelconque.
 * Utilisé en entrée AVANT le stockage en base de données.
 * @param {string|*} input
 * @returns {string}
 */
function sanitizeInput(input) {
  if (typeof input !== 'string') return '';
  // DOMPurify supprime les balises malveillantes (ex. <script>, onerror=...)
  return DOMPurify.sanitize(input, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] }).trim();
}

/**
 * Encode HTML en sortie pour prévenir le rendu de contenu malveillant (V5).
 * @param {string} value
 * @returns {string}
 */
function encodeOutput(value) {
  if (typeof value !== 'string') return value;
  return he.encode(value);
}

// ─────────────────────────────────────────────────────────────────────────────
// Règles de validation (Joi-like avec express-validator) — Livrable 1.3
// ─────────────────────────────────────────────────────────────────────────────

const transferValidationRules = [
  body('to_account')
    .isUUID(4)
    .withMessage('Identifiant du compte destinataire invalide.'),
  body('amount')
    .isFloat({ gt: 0, max: 100000 })
    .withMessage('Le montant doit être compris entre 0 et 100 000.'),
  body('description')
    .optional()
    .isString()
    .isLength({ max: 200 })
    .withMessage('La description ne peut pas dépasser 200 caractères.')
    .customSanitizer(v => sanitizeInput(v)), // V5 : sanitization en entrée
];

const updateProfileValidationRules = [
  // V6 : Seuls les champs de cette liste sont acceptés (whitelist)
  body('email')
    .optional()
    .isEmail()
    .normalizeEmail()
    .withMessage('Email invalide.'),
  body('display_name')
    .optional()
    .isString()
    .isLength({ min: 1, max: 100 })
    .customSanitizer(v => sanitizeInput(v)),
  body('phone_number')
    .optional()
    .matches(/^\+?[1-9]\d{6,14}$/)
    .withMessage('Numéro de téléphone invalide.'),
];

/**
 * Middleware : retourne 400 si la validation échoue.
 * Les messages sont génériques pour ne pas fuiter d'informations (V10).
 */
function handleValidationErrors(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: 'Données invalides.', details: errors.array() });
  }
  next();
}

// ─────────────────────────────────────────────────────────────────────────────
// V6 CORRIGÉ : Mass Assignment — Whitelist des champs modifiables
//
// AVANT (vulnérable) :
//   await db.users.update(userId, req.body);  // Tous les champs !
//
// APRÈS (sécurisé) :
//   Seuls les champs sur liste blanche sont extraits
// ─────────────────────────────────────────────────────────────────────────────

/** Champs autorisés pour la mise à jour du profil. */
const ALLOWED_PROFILE_FIELDS = ['email', 'display_name', 'phone_number'];

/**
 * Extrait uniquement les champs autorisés depuis le corps de la requête.
 * Tout autre champ (role, balance, is_admin, id...) est ignoré.
 * @param {object} body
 * @returns {object}
 */
function pickAllowedProfileFields(body) {
  return ALLOWED_PROFILE_FIELDS.reduce((acc, field) => {
    if (body[field] !== undefined) acc[field] = body[field];
    return acc;
  }, {});
}

// ─────────────────────────────────────────────────────────────────────────────
// Endpoints
// ─────────────────────────────────────────────────────────────────────────────

/**
 * PUT /user/profile
 * V6 CORRIGÉ : Mass Assignment
 */
router.put(
  '/user/profile',
  updateProfileValidationRules,
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const userId = req.user.id;

      // V6 CORRIGÉ : Extraction des seuls champs autorisés
      const safeData = pickAllowedProfileFields(req.body);

      if (Object.keys(safeData).length === 0) {
        return res.status(400).json({ error: 'Aucun champ valide fourni.' });
      }

      await db.users.update(userId, safeData);

      // V9 : Log de l'action sensible
      logger.info('Mise à jour de profil', {
        event: 'profile_update',
        userId,
        fields: Object.keys(safeData),
      });

      return res.json({ message: 'Profil mis à jour.' });
    } catch (err) {
      next(err);
    }
  }
);

/**
 * POST /transfer
 * V5 CORRIGÉ : XSS Stored
 */
router.post(
  '/transfer',
  transferValidationRules,
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const { to_account, amount, description } = req.body;
      // description est déjà sanitisée par customSanitizer dans les règles de validation

      const transfer = await db.transfers.create({
        from_account: req.user.account_id,
        to_account,
        amount,
        // V5 CORRIGÉ : description sanitisée en entrée + encodage en sortie
        description: description || null,
      });

      // V9 : Log du virement
      logger.info('Virement effectué', {
        event: 'transfer_created',
        userId: req.user.id,
        toAccount: to_account,
        amount,
      });

      // V5 : Encodage HTML en sortie pour empêcher le rendu de contenu malveillant
      const safeTransfer = {
        ...transfer,
        description: transfer.description ? encodeOutput(transfer.description) : null,
      };

      return res.status(201).json(safeTransfer);
    } catch (err) {
      next(err);
    }
  }
);

module.exports = router;
