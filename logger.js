/**
 * logger.js - Logging structuré JSON pour NeoBank Digital
 * Livrable 3.4 : Logging de sécurité complet
 * V9 CORRIGÉ : Logging insuffisant des actions sensibles
 */

'use strict';

const { createLogger, format, transports } = require('winston');
const { v4: uuidv4 } = require('uuid');

const { combine, timestamp, json, errors, printf } = format;

/**
 * Format structuré JSON enrichi d'un correlationId.
 * Facilite la corrélation des logs dans les systèmes de monitoring (SIEM).
 */
const structuredFormat = combine(
  errors({ stack: true }),
  timestamp({ format: 'ISO' }),
  json()
);

/**
 * Retourne un logger nommé pour un composant donné.
 * @param {string} name  Ex. 'neobank.payments', 'neobank.auth'
 */
function getLogger(name) {
  return createLogger({
    level: process.env.LOG_LEVEL || 'info',
    defaultMeta: { service: name },
    format: structuredFormat,
    transports: [
      new transports.Console(),
      ...(process.env.LOG_FILE
        ? [new transports.File({ filename: process.env.LOG_FILE })]
        : []),
    ],
  });
}

/**
 * Middleware Express : attache un correlationId unique à chaque requête.
 * Ce correlationId doit être propagé dans tous les logs d'une même requête.
 */
function correlationMiddleware(req, res, next) {
  req.correlationId = req.headers['x-correlation-id'] || uuidv4();
  res.setHeader('X-Correlation-Id', req.correlationId);
  next();
}

module.exports = { getLogger, correlationMiddleware };
