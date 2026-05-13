# Security Demo Project

Spring Boot sandbox voor security-implementaties. Zie `README.md` voor gebruik en curl-voorbeelden.

## Stack
- Java 25
- Spring Boot 4.0.x
- Spring Security + Spring Authorization Server
- Spring Data JPA + Hibernate
- H2 (in-memory, simuleert PostgreSQL)

## Doel
Dit project dient als sandbox voor het uitproberen van security-gerelateerde implementaties.  
Elke POC is zelfstandig en hoeft niet productie-ready te zijn.

---

## Hoe je context meegeeft voor een nieuwe POC

Geef bij elke nieuwe POC de volgende informatie:

### 1. Wat wil je demonstreren?
Beschrijf kort het security-concept:
> "Ik wil JWT-authenticatie implementeren met refresh tokens"

### 2. Scope
Wat hoort WEL en NIET in de POC:
> "Alleen authenticatie, geen autorisatie op endpoints nog"

### 3. Aannames / constraints
> "Gebruikers staan hardcoded, geen echte database integratie nodig"

### 4. Gewenst eindresultaat
Wat moet je kunnen doen/zien na de POC:
> "Ik wil via Postman een token ophalen en een beveiligd endpoint aanroepen"

---

## Encryptie — Referentiekader

### 1. Algoritmen
- **AES-GCM** — niet-deterministisch, biedt vertrouwelijkheid + integriteit; gebruikt in `AesGcmConverter` (app-laag)
- **AES-SIV** — deterministisch, maakt exact zoeken mogelijk (niet actief geïmplementeerd)
- **AES-CBC/AEAD** — gebruikt op database-niveau via PostgreSQL `pgcrypto` (in H2: `H2EncryptFunctions`)
- **HMAC-SHA256** — zoekindex naast AES-GCM: deterministisch hash van plaintext, onthult niets over de waarde

### 2. Sleutelbeheer (productie-referentie)
- **DEK** (Data Encryption Key) — versleutelt de data, per tabel/context
- **KEK** (Key Encryption Key) — versleutelt de DEKs; beheerd via Elytron Keystore (JBoss EAP)
- **KEK-doorgave** — via sessievariabele `application_name` aan de DB-connectie (`${ENC::encryption-resolver:...}`)
- **KEK-rotatie** — alle DEKs herversleutelen in één transactie met `REPEATABLE READ` isolatie

### 3. Implementatie-opties (Java)
| Optie | Techniek | Zoeken mogelijk? |
|-------|----------|-----------------|
| 3.1 | `AttributeConverter` + AES-GCM | Nee (willekeurige IV) |
| 3.3 | `AttributeConverter` + AES-GCM + HMAC-index | Ja, via HMAC-kolom |
| 3.4 | `@ColumnTransformer` + DB-functies (pgcrypto) | Ja, via DB-functies |

**Actief in POC 6:** combinatie van 3.1 + 3.3 + 3.4 (dubbele encryptie, HMAC per veld).

### 4. Beveiligingseisen (aandachtspunten voor productie)
- Geen logging van sessievariabelen (`application_name`)
- Geen core dumps op OS
- Geen debug logging op JBoss EAP
- KEK-applicatie communiceert alleen via gescheiden kanaal (niet HTTP, browser of SSH)

---

## NL GOV Standaarden (toegepast)

### API Design Rules (ADR v2.1.0)

**Bron:** [gitdocumentatie.logius.nl/publicatie/api/adr/2.1.0](https://gitdocumentatie.logius.nl/publicatie/api/adr/2.1.0/)  
**Status:** Verplicht (pas-toe-of-leg-uit, Forum Standaardisatie)

| Regel | Toepassing | Bestand |
|-------|-----------|---------|
| Major versie in URI-pad | `/v1/poc-6`, `/v1/poc-7` | `DemoController` |
| Kebab-case padsegmenten | `poc-6`, `poc-7` | `DemoController` |
| Operaties als `_` sub-resources | `/_perf`, `/_admin` | `DemoController` |
| Zoekfilter als query-param op collectie | `GET /v1/poc-6?naam=` | `DemoController` |
| `API-Version` response header | Op alle `/v1/` responses | `SecurityHeadersFilter` |
| Security headers (sectie 3.8) | `Cache-Control`, `CSP`, `HSTS`, `X-Content-Type-Options`, `X-Frame-Options` | `SecurityHeadersFilter` |
| `application/problem+json` (RFC 9457) | Globale foutafhandeling | `ApiExceptionHandler` |

### OAuth 2.0 NL Profiel (v1.1.0) + OIDC NL GOV (v1.0.1)

**Bron:** [gitdocumentatie.logius.nl/publicatie/api/oauth](https://gitdocumentatie.logius.nl/publicatie/api/oauth/)  
**Status:** Verplicht (pas-toe-of-leg-uit, Forum Standaardisatie)

| Regel | Toepassing | Bestand |
|-------|-----------|---------|
| Authorization Server met JWT access tokens (RFC 9068) | Spring Authorization Server op `http://localhost:8080` | `AuthorizationServerConfig` |
| `authorization_code` + PKCE verplicht voor public clients | `poc-web-client` met `requireProofKey(true)` | `AuthorizationServerConfig` |
| `client_credentials` voor machine-to-machine | `poc-service-client` | `AuthorizationServerConfig` |
| Access tokens via `Authorization: Bearer` header | Resource server JWT filter | `SecurityConfig` |
| Implicit grant verboden | Niet geconfigureerd | `AuthorizationServerConfig` |
| Betrouwbaarheidsniveaus (eIDAS) | In-memory gebruiker als placeholder; in productie DigiD/eHerkenning | `AuthorizationServerConfig` |

**POC-afwijkingen:**
- `client_secret_basic` i.p.v. `private_key_jwt` (verplicht per NL GOV OAuth)
- In-memory gebruiker i.p.v. DigiD/eHerkenning
- `anyRequest().permitAll()` — tokens niet afgedwongen in demo

---

## Actieve POCs

### POC 6 — Dubbele encryptie (app + DB) met HMAC-zoekindex

**Concept:** 3.1 + 3.3 + 3.4 — AES-GCM (Java) + `@ColumnTransformer` (DB) + HMAC-index per veld

**Datastroom write:** `plaintext → AES-GCM (Java) → ENCRYPT_STRING (H2/DB) → opslag`  
**Datastroom read:**  `DB → DECRYPT_STRING (H2/DB) → AES-GCM decrypt (Java) → plaintext`  
**Zoeken:** `hmacBase64(zoekterm)` vergeleken met `naam_hmac` / `notitie_hmac` kolom

**Endpoints:**
```
POST /v1/poc-6                     { "naam": "...", "notitie": "...", "openbaar": "..." }
GET  /v1/poc-6                     Alle records
GET  /v1/poc-6?naam=<waarde>       Zoeken via HMAC-index van naam
GET  /v1/poc-6?notitie=<waarde>    Zoeken via HMAC-index van notitie
GET  /v1/poc-6/{id}                Enkel record
GET  /v1/poc-6/_perf?operatie=...  Performance meting (lijst / zoek-naam / zoek-notitie / enkel)
```

**Bestanden:**
- `domain/EncryptedRecord.java` — entity (tabel: `poc6`)
- `repository/EncryptedRecordRepository.java`
- `seeder/EncryptedRecordSeeder.java` — 10.000 testrecords
- `controller/EncryptionController.java` — endpoints `/v1/poc-6/**`
- `service/EncryptionService.java` — opslaan (incl. HMAC-berekening), zoeken, count
- `crypto/AesGcmConverter.java` — AES-GCM JPA converter
- `crypto/H2EncryptFunctions.java` — H2 SQL-functies (simuleert pgcrypto)
- `config/H2FunctionRegistrar.java` — registreert ENCRYPT_STRING / DECRYPT_STRING

---

### POC 7 — Row Level Security (RLS)

**Concept:** PostgreSQL RLS gesimuleerd in H2 via Hibernate `@Filter`

**Datastroom:** `X-Eigenaar-Id header → RlsContext (ThreadLocal) → Hibernate @Filter → WHERE eigenaar_id = :userId`  
**PostgreSQL-equivalent:** `SET LOCAL app.current_user_id = ?` + `CREATE POLICY ... USING (eigenaar_id = current_setting(...))`

**Gotcha:** `EntityManager.find()` bypast Hibernate-filters → `findByIdMetFilter()` via JPQL in repository

**Endpoints:**
```
POST /v1/poc-7              { "inhoud": "...", "openbaar": "..." }  + X-Eigenaar-Id header
GET  /v1/poc-7              Eigen records (RLS actief via X-Eigenaar-Id)
GET  /v1/poc-7/{id}         Enkel record — 404 als niet van jou (bewust: onthult geen toegang)
GET  /v1/poc-7/_admin       Alle records zonder filter (BYPASSRLS equivalent)
```

**Seed-data:** 3 gebruikers (gebruiker-1: 3 records, gebruiker-2: 2, gebruiker-3: 1). Zonder header → `[]`.

**Bestanden:**
- `domain/RlsRecord.java` — entity (tabel: `poc7`)
- `repository/RlsRecordRepository.java`
- `seeder/RlsRecordSeeder.java` — 6 testrecords voor 3 gebruikers
- `controller/RlsController.java` — endpoints `/v1/poc-7/**`
- `service/RlsService.java` — RLS-filter activering, findVanEigenaar, findById, findAlles
- `rls/RlsContext.java` — ThreadLocal eigenaar-id
- `rls/RlsHandlerInterceptor.java` — leest X-Eigenaar-Id, zet/ruimt RlsContext
- `rls/RlsConfig.java` — registreert interceptor op `/v1/poc-7/**`
