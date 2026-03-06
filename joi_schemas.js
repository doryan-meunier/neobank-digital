/**
 * joi_schemas.js - Schémas de validation Joi pour NeoBank Digital
 * Livrable 1.3 : Validation stricte côté Node.js/Express
 *
 * Utilise Joi pour des contraintes strictes : types, longueurs, regex, plages.
 * Les messages d'erreur sont génériques pour éviter les fuites d'informations (V10).
 */

'use strict';

const Joi = require('joi');

// ─────────────────────────────────────────────────────────────────────────────
// Options globales : messages d'erreur génériques (V10)
// ─────────────────────────────────────────────────────────────────────────────
const JOI_OPTIONS = {
  abortEarly: false,       // Collecte toutes les erreurs, pas seulement la première
  allowUnknown: false,     // Rejette les champs non déclarés (Mass Assignment, V6)
  stripUnknown: false,
  errors: {
    wrap: { label: false }, // Messages sans guillemets autour du nom du champ
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// Primitifs réutilisables
// ─────────────────────────────────────────────────────────────────────────────
const uuidV4 = Joi.string()
  .uuid({ version: 'uuidv4' })
  .required()
  .messages({ 'string.guid': 'Identifiant invalide.' });

const positiveAmount = Joi.number()
  .positive()
  .max(100_000)
  .precision(2)
  .required()
  .messages({
    'number.positive': 'Le montant doit être positif.',
    'number.max': 'Le montant ne peut pas dépasser 100 000 €.',
  });

const safeString = (maxLen = 255) =>
  Joi.string()
    .max(maxLen)
    // Interdit les balises HTML/script (v5, défense en profondeur)
    .pattern(/^[^<>]*$/, { name: 'noHtmlTags' })
    .messages({
      'string.pattern.name': 'Les caractères < et > ne sont pas autorisés.',
    });

// ─────────────────────────────────────────────────────────────────────────────
// Authentification
// ─────────────────────────────────────────────────────────────────────────────
const loginSchema = Joi.object({
  username: Joi.string()
    .alphanum()
    .min(3)
    .max(50)
    .required()
    .messages({ 'any.required': 'Identifiants requis.' }),
  password: Joi.string()
    .min(8)
    .max(128)
    .required()
    .messages({ 'any.required': 'Identifiants requis.' }),
}).options(JOI_OPTIONS);

// ─────────────────────────────────────────────────────────────────────────────
// Virement (V5 - XSS)
// ─────────────────────────────────────────────────────────────────────────────
const transferSchema = Joi.object({
  to_account: uuidV4,
  amount: positiveAmount,
  description: safeString(200).optional().allow(null, '').messages({
    'string.max': 'La description ne peut pas dépasser 200 caractères.',
  }),
}).options(JOI_OPTIONS);

// ─────────────────────────────────────────────────────────────────────────────
// Mise à jour du profil (V6 - Mass Assignment)
// Seuls les champs listés ici sont acceptés.
// ─────────────────────────────────────────────────────────────────────────────
const updateProfileSchema = Joi.object({
  email: Joi.string().email().max(255).optional().messages({
    'string.email': 'Adresse email invalide.',
  }),
  display_name: safeString(100).optional(),
  phone_number: Joi.string()
    .pattern(/^\+?[1-9]\d{6,14}$/)
    .optional()
    .messages({ 'string.pattern.base': 'Numéro de téléphone invalide.' }),
  // IMPORTANT : 'role', 'balance', 'is_admin', 'id' sont intentionnellement absents
}).options(JOI_OPTIONS);

// ─────────────────────────────────────────────────────────────────────────────
// Middleware Express : valide req.body contre un schéma Joi
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Crée un middleware de validation Joi.
 * @param {Joi.Schema} schema
 * @returns {import('express').RequestHandler}
 */
function validate(schema) {
  return (req, res, next) => {
    const { error } = schema.validate(req.body, JOI_OPTIONS);
    if (error) {
      // V10 : Messages génériques sans détails techniques
      return res.status(400).json({
        error: 'Données invalides.',
        details: error.details.map(d => ({ field: d.path.join('.'), message: d.message })),
      });
    }
    next();
  };
}

module.exports = {
  loginSchema,
  transferSchema,
  updateProfileSchema,
  validate,
};
