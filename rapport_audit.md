# Rapport d'Audit Sécurité — NeoBank Digital
**CLOE855 - Projet de Synthèse DEV**  
**Date :** Mars 2026  
**Équipe :** EISI I1  

---

## Livrable 4.2 : Tableau de remédiation complet

### Annexe A — Tableau de remédiation des 12 vulnérabilités

| ID | Vulnérabilité | Catégorie OWASP | Criticité | Solution implémentée | Fichier(s) modifié(s) | Test de validation |
|----|--------------|-----------------|-----------|---------------------|----------------------|-------------------|
| **V1** | Injection SQL dans la recherche de transactions | A03:2021 - Injection | 🔴 CRITIQUE | Remplacement des f-strings par l'ORM SQLAlchemy (requêtes paramétrées). Validation Pydantic des entrées avec rejet des patterns SQL dangereux (`--`, `;`, `UNION`, `DROP`). | `accounts_service.py` – `search_transactions()` ; `schemas.py` – `TransactionSearchRequest` | `tests/test_security.py::TestSQLInjection::test_sql_injection_payloads_rejected_by_schema` |
| **V2** | Broken Authentication - JWT sans expiration | A07:2021 - Auth Failures | 🔴 CRITIQUE | Access token avec expiration 15 min + refresh token 7 jours. Claims minimaux + JTI (anti-replay). Secret externalisé. Rotation du refresh token à chaque utilisation. | `auth_service.py` – `create_access_token()`, `create_refresh_token()` ; `models.py` – `RefreshToken` | `tests/test_security.py::TestJWTExpiration` |
| **V3** | IDOR - Accès aux comptes d'autres utilisateurs | A01:2021 - Broken Access Control | 🔴 CRITIQUE | Vérification de propriété systématique dans `verify_account_ownership()`. Retourne HTTP 403 (pas 404) pour ne pas révéler l'existence. Log des tentatives non autorisées. | `accounts_service.py` – `verify_account_ownership()`, `get_account()`, `search_transactions()` | `tests/test_security.py::TestIDOR` |
| **V4** | Secrets codés en dur dans le code source | A02:2021 - Cryptographic Failures | 🔴 CRITIQUE | Suppression de `DB_PASSWORD`, `SECRET_KEY` hardcodés. Variables d'environnement via `python-dotenv`. Intégration AWS Secrets Manager pour la production. `.env.example` sans valeurs sensibles. `.gitignore` mis à jour. | `database.py`, `auth_service.py`, `secrets_manager.py`, `.env.example`, `.gitignore` | `tests/test_security.py::TestSecrets::test_no_hardcoded_passwords_in_source` |
| **V5** | XSS Stored dans les commentaires de transaction | A03:2021 - Injection | 🟠 MAJEURE | Sanitization avec DOMPurify (suppression de toutes balises HTML/JS) avant stockage. Validation Pydantic avec regex et suppression des balises côté Python. Encodage HTML en sortie via `he.encode()`. Content Security Policy (CSP) stricte via Helmet. | `payments_service.js` – `sanitizeInput()`, `transferValidationRules` ; `schemas.py` – `TransferRequest` ; `app.js` – Helmet CSP | `tests/test_security.py::TestXSS` ; `tests/test_security.spec.js::XSS Protection` |
| **V6** | Mass Assignment lors de la mise à jour du profil | A04:2021 - Insecure Design | 🟠 MAJEURE | DTO `UpdateProfileRequest` avec whitelist explicite (`email`, `display_name`, `phone_number`). `extra = "forbid"` côté Pydantic. `pickAllowedProfileFields()` côté Express. Les champs `role`, `balance`, `is_admin`, `id` sont absents du DTO. | `schemas.py` – `UpdateProfileRequest` ; `payments_service.js` – `pickAllowedProfileFields()`, `updateProfileValidationRules` | `tests/test_security.py::TestXSS::test_mass_assignment_rejected_by_update_profile_schema` ; `tests/test_security.spec.js::Mass Assignment Protection` |
| **V7** | Absence de rate limiting sur l'endpoint de login | A07:2021 - Auth Failures | 🟠 MAJEURE | Rate limiting par IP : 10 tentatives / 15 min sur `/login` (express-rate-limit). Slow-down progressif après 5 tentatives. Header `Retry-After` dans la réponse 429. Rate limit global 200 req/15 min. | `app.js` – `loginLimiter`, `loginSlowDown`, `globalLimiter` | `tests/test_security.spec.js::Rate Limiting` |
| **V8** | Dépendances avec CVE critiques non mises à jour | A06:2021 - Vulnerable Components | 🟠 MAJEURE | Mise à jour de toutes les dépendances vulnerables Python et Node.js. Justification documentée dans `requirements.txt` et `package.json`. Scan automatisé pip-audit + npm audit dans le pipeline CI/CD. | `requirements.txt` (7 mises à jour) ; `package.json` (6 mises à jour) ; `.github/workflows/security.yml` | CI/CD Job `sca-python` + `sca-nodejs` |
| **V9** | Logging insuffisant des actions sensibles | A09:2021 - Logging Failures | 🟡 MODÉRÉE | Logging structuré JSON avec correlationId. Log des authentifications (succès/échecs), virements, modifications de profil, tentatives IDOR. Filtre `SensitiveDataFilter` pour masquer les données sensibles dans les logs. | `logging_config.py`, `auth_service.py`, `accounts_service.py`, `logger.js`, `app.js` | Vérification manuelle des logs en mode test |
| **V10** | Messages d'erreur trop verbeux exposant la stack trace | A04:2021 - Insecure Design | 🟡 MODÉRÉE | Gestionnaire d'erreurs global en production : message générique + correlationId uniquement. Stack trace uniquement dans les logs serveur. Messages d'authentification génériques ("Identifiants incorrects." vs "User X not found in database accounts.users"). | `app.js` – gestionnaire d'erreurs ; `auth_service.py` – messages d'erreur | `tests/test_security.spec.js` (réponses sans stack trace) |
| **V11** | Absence de validation du Content-Type | A08:2021 - Software and Data Integrity | 🟡 MODÉRÉE | Middleware Express qui rejette (HTTP 415) toute requête POST/PUT/PATCH sans `Content-Type: application/json`. Limite de taille du body à 100 KB (protection DoS). | `app.js` – middleware Content-Type | `tests/test_security.spec.js::Validation Content-Type` |
| **V12** | CORS trop permissif (Access-Control-Allow-Origin: *) | A05:2021 - Security Misconfiguration | 🟡 MODÉRÉE | Whitelist explicite des origines autorisées via `CORS_ALLOWED_ORIGINS` (variable d'environnement). Rejet des origines non listées avec log d'avertissement. `credentials: true` pour les cookies d'authentification. | `app.js` – `corsOptions` ; `payments_service.js` – `corsOptions` | `tests/test_security.spec.js::CORS restrictif` |

---

## Résumé des phases

### Phase 1 — Injections et validation des entrées

#### Livrable 1.1 : Injection SQL (V1) — `accounts_service.py`

**Vulnérabilité :** Interpolation directe des paramètres utilisateur dans la requête SQL :
```python
# VULNÉRABLE
query = f"SELECT * FROM transactions WHERE user_id = '{user_id}' AND description LIKE '%{keyword}%'"
cursor.execute(query)
```

**Correction :** ORM SQLAlchemy avec requêtes entièrement paramétrées :
```python
# CORRIGÉ
transactions = (
    db.query(Transaction)
    .filter(
        Transaction.sender_account_id == account.id,
        Transaction.description.ilike(f"%{params.keyword}%"),  # paramètre lié, jamais interpolé
    )
    .limit(100)
    .all()
)
```

#### Livrable 1.2 : XSS Stored (V5) — `payments_service.js` + `schemas.py`

**Vulnérabilité :** Description du virement stockée sans sanitization.

**Correction :**
1. **Sanitization en entrée** (DOMPurify/Pydantic regex) — supprime toutes les balises HTML/JS
2. **Encodage HTML en sortie** (`he.encode()`) — empêche le rendu des caractères spéciaux
3. **CSP stricte** (`script-src 'self'`) — bloque les scripts inline même si (1) et (2) échouent

#### Livrable 1.3 : Schémas de validation

| Schéma | Fichier | Contraintes |
|--------|---------|-------------|
| `TransactionSearchRequest` | `schemas.py` | keyword: 1-100 chars, rejette `--`,`;`,`UNION`,`DROP`, balises HTML |
| `TransferRequest` | `schemas.py` | amount: 0-100000, description: max 200 chars, sanitisée |
| `UpdateProfileRequest` | `schemas.py` | email: RFC5322, phone: E.164, extra="forbid" |
| `LoginRequest` | `schemas.py` | username: alphanum 3-50, password: 8-128 |
| `loginSchema` | `joi_schemas.js` | username: alphanum 3-50, password 8-128 |
| `transferSchema` | `joi_schemas.js` | amount >0 max 100000, description no HTML |
| `updateProfileSchema` | `joi_schemas.js` | Seuls email/display_name/phone autorisés |

---

### Phase 2 — Authentification et contrôle d'accès

#### Livrable 2.1 : JWT sécurisé (V2) — `auth_service.py`

| Aspect | Avant (vulnérable) | Après (corrigé) |
|--------|--------------------|-----------------|
| Expiration | Aucune | 15 min (access) + 7 jours (refresh) |
| Secret | Codé en dur (`"super_secret_key_123"`) | Variable d'environnement (min 32 chars) |
| Algorithme | HS256 (configurable) | HS256 par défaut, RS256/ES256 recommandé en prod |
| Anti-replay | Aucun | JTI (UUID unique par token) |
| Refresh | Aucun | Rotation à chaque utilisation, hash en base |

#### Livrable 2.2 : IDOR (V3) — `accounts_service.py`

```python
# AVANT (vulnérable)
account = db.get_account(account_id)
return account  # Aucune vérification de propriété !

# APRÈS (corrigé)
def verify_account_ownership(account_id, current_user, db):
    account = db.query(Account).filter(Account.id == account_uuid).first()
    if account is None or str(account.owner_id) != str(current_user.id):
        logger.warning("Tentative d'accès IDOR", extra={...})
        raise HTTPException(status_code=403, detail="Accès refusé.")
    return account
```

#### Livrable 2.3 : Mass Assignment (V6) — `payments_service.js` + `schemas.py`

Whitelist des champs modifiables : `email`, `display_name`, `phone_number`  
Champs interdits : `role`, `balance`, `is_admin`, `id`, `owner_id`, `hashed_password`

#### Livrable 2.4 : Rate Limiting (V7) — `app.js`

| Endpoint | Limite | Fenêtre | Slow-down |
|----------|--------|---------|-----------|
| `/login` | 10 req | 15 min | +500ms après 5 req |
| Global | 200 req | 15 min | Non |

---

### Phase 3 — Configuration et dépendances

#### Livrable 3.1 : Gestion sécurisée des secrets (V4)

- `secrets_manager.py` : Abstraction qui lit depuis AWS Secrets Manager en production et depuis `.env` en développement
- `.env.example` : Modèle avec placeholders `CHANGE_ME`
- `.gitignore` : `.env` et tous les fichiers de secrets exclus

#### Livrable 3.2 : Mise à jour des dépendances (V8)

**Python** (`requirements.txt`) :

| Package | Ancienne version | Nouvelle version | CVE corrigée |
|---------|-----------------|-----------------|--------------|
| fastapi | 0.68.0 | 0.115.0 | CVE-2021-32677 (Medium) |
| pydantic | 1.7.0 | 2.9.2 | CVE-2021-29510 (High) |
| sqlalchemy | 1.3.0 | 2.0.36 | CVE-2019-7164 (Critical) |
| python-jose | 3.1.0 | 3.4.0 | CVE-2022-29217 (High) |
| requests | 2.20.0 | 2.32.3 | CVE-2018-18074 (High) |
| pyyaml | 5.1 | 6.0.2 | CVE-2020-14343 (Critical) |
| pillow | 6.0.0 | 11.0.0 | CVE-2021-23437 (Critical) |

**Node.js** (`package.json`) :

| Package | Ancienne version | Nouvelle version | CVE corrigée |
|---------|-----------------|-----------------|--------------|
| express | 4.16.0 | 4.21.1 | CVE-2022-24999 (High) |
| lodash | 4.17.11 | 4.17.21 | CVE-2020-8203 (High) |
| axios | 0.18.0 | 1.7.7 | CVE-2019-10742 (High) |
| jsonwebtoken | 8.3.0 | 9.0.2 | CVE-2022-23529 (Critical) |
| mongoose | 5.7.0 | 8.7.3 | CVE-2022-2564 (Critical) |
| helmet | 3.12.0 | 8.0.0 | Headers modernes, HSTS, CSP v3 |

#### Livrable 3.3 : Configuration sécurisée (V10, V11, V12)

| Mesure | Fichier | Détail |
|--------|---------|--------|
| CORS restrictif | `app.js`, `payments_service.js` | Whitelist via `CORS_ALLOWED_ORIGINS` |
| Headers Helmet | `app.js`, `payments_service.js` | HSTS, CSP, noSniff, referrerPolicy |
| Validation Content-Type | `app.js` | Middleware 415 si non-JSON |
| Gestion erreurs | `app.js` | Message générique en prod, stack trace dans logs |

#### Livrable 3.4 : Logging de sécurité (V9)

| Événement loggué | Niveau | Données incluses | Données exclues |
|-----------------|--------|-----------------|----------------|
| Connexion réussie | INFO | user_id, IP, timestamp | mot de passe, token |
| Échec de connexion | WARN | username, IP, timestamp | mot de passe |
| Tentative IDOR | WARN | user_id, target_id, owner_id | — |
| Virement | INFO | user_id, to_account, amount | IBAN complet |
| Rate limit atteint | WARN | IP, correlationId | — |
| Erreur applicative | ERROR | stack trace, correlationId | Données utilisateur |

---

### Phase 4 — Tests et documentation

#### Livrable 4.1 : Tests de sécurité automatisés

**Python** (`tests/test_security.py`) :

| Classe de test | Couverture |
|---------------|-----------|
| `TestSQLInjection` | 8 payloads SQL classiques rejetés par Pydantic |
| `TestJWTExpiration` | Token valide/expiré/sans exp/mauvais type |
| `TestIDOR` | 403 pour compte d'autrui, réussite pour son propre compte, 403 vs 404 |
| `TestXSS` | 7 payloads XSS sanitisés par Pydantic |
| `TestSecrets` | Absence de secrets hardcodés dans les fichiers source |

**Node.js** (`tests/test_security.spec.js`) :

| Suite de test | Couverture |
|--------------|-----------|
| `Rate Limiting` | 429 après 10+ tentatives, header Retry-After |
| `XSS Protection` | Sanitization des 4 payloads XSS classiques |
| `Mass Assignment` | Rejet des champs `role`, `balance`, `is_admin` |
| `CORS restrictif` | Accepte l'origine autorisée, rejette les autres, jamais `*` |
| `Validation Content-Type` | 415 pour non-JSON, accepte application/json |
| `Security Headers` | noSniff, HSTS, CSP, X-Frame-Options |

#### Livrable 4.3 : Pipeline CI/CD sécurisé

Fichier : `.github/workflows/security.yml`

```
Push/PR → main ou develop
    │
    ├── SAST Python (Bandit) ────────────────────────► SARIF → GitHub Security
    ├── SAST JavaScript (ESLint Security) ───────────► SARIF → GitHub Security  
    ├── SCA Python (pip-audit) ──────────────────────► Rapport JSON
    ├── SCA Node.js (npm audit) ─────────────────────► Rapport JSON
    ├── Scan secrets (Gitleaks) ─────────────────────► SARIF → GitHub Security
    │
    ├── Tests Python (pytest) ───────────────────────► Coverage XML
    ├── Tests Node.js (Jest) ────────────────────────► Coverage JSON
    │
    └── Security Gate ───────────────────────────────► Bloque le merge si échec
```

---

## Annexe B — Référence OWASP Top 10 2021

| Code | Catégorie | Vulnérabilités du projet | Corrigé |
|------|-----------|--------------------------|---------|
| A01:2021 | Broken Access Control | V3 (IDOR) | ✅ `verify_account_ownership()` |
| A02:2021 | Cryptographic Failures | V4 (secrets en dur) | ✅ `secrets_manager.py` + `.env` |
| A03:2021 | Injection | V1 (SQL), V5 (XSS) | ✅ ORM + DOMPurify + CSP |
| A04:2021 | Insecure Design | V6 (Mass Assignment), V10 | ✅ DTO whitelist + erreurs génériques |
| A05:2021 | Security Misconfiguration | V12 (CORS) | ✅ CORS whitelist |
| A06:2021 | Vulnerable Components | V8 (dépendances) | ✅ Toutes dépendances mises à jour |
| A07:2021 | Auth Failures | V2 (JWT), V7 (brute force) | ✅ JWT avec exp + rate limiting |
| A09:2021 | Logging Failures | V9 (logging insuffisant) | ✅ JSON structuré + correlationId |

---

*Rapport produit dans le cadre de l'atelier CLOE855 — Développer et sécuriser une solution cloud.*
