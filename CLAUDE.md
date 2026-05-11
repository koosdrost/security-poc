# Security Demo Project

Spring Boot 4.x demo project for POC-ing security implementations.

## Stack
- Java 25
- Spring Boot 4.0.x
- Spring Security
- Spring Data JPA
- H2 (in-memory database)

## Doel
Dit project dient als sandbox voor het uitproberen van security-gerelateerde implementaties. Elke POC is zelfstandig en hoeft niet productie-ready te zijn.

---

## Hoe je context meegeeft voor een POC

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

## Encryptie — Referentiekader (uit encryptie.pdf)

### 1. Algoritmen
- **1.1** AES-GCM — niet-deterministisch, biedt vertrouwelijkheid + integriteit, gebruikt in Java-applicatie
- **1.2** AES-SIV — deterministisch, maakt exact zoeken mogelijk
- **1.3** AES-CBC in AEAD-modus — gebruikt op database-niveau via PostgreSQL `pgcrypto`
- **1.4** HMAC — gebruikt als zoekindex naast AES-GCM (optie 3)

### 2. Sleutelbeheer — Envelope Encryption
- **2.1** DEK (Data Encryption Key) — versleutelt de data, per tabel/context, opgeslagen in eigen DB-tabel
- **2.2** KEK (Key Encryption Key) — versleutelt de DEKs, 1 actief tegelijk
- **2.3** KEK wordt beheerd via **Elytron Keystore** (JBoss EAP) en doorgegeven via sessievariabele `${ENC::encryption-resolver:...}`
- **2.4** DEKs worden opgeslagen in tabel `data_encryption_key` met versienummer en actief-vlag

### 3. Implementatie-opties (Java)
- **3.1** `AttributeConverter` + AES-GCM → geen zoeken mogelijk (niet-deterministisch)
- **3.2** `AttributeConverter` + AES-SIV → exact zoeken mogelijk (deterministisch)
- **3.3** `AttributeConverter` + AES-GCM + HMAC-index → zoeken via HMAC van zoekterm
- **3.4** `ColumnTransformer` + AES-CBC/AEAD in PostgreSQL → zoeken via DB-functies `encrypt_string` / `decrypt_string`

### 4. Referentie-implementatie (optie 3.4)
- **4.1** Spring Boot op JBoss EAP met PostgreSQL
- **4.2** `@ColumnTransformer` roept PostgreSQL-functies aan voor encrypt/decrypt
- **4.3** KEK wordt via sessievariabele (`application_name`) doorgegeven aan DB-connectie
- **4.4** Connection-factory geconfigureerd met `${ENC::encryption-resolver:...}` in JBoss EAP datasource
- **4.5** JPA-entity gebruikt `@ColumnTransformer(read = "decrypt_string(...)", write = "encrypt_string(?, ...)")`

### 5. KEK-rotatie
- **5.1** Patroon: **Shamir's Secret Sharing (SSS)** — minimaal 3 van 5 beheerders vereist
- **5.2** Rollen: technisch sleutelbeheerders (toegang tot shares) + ceremoniemeester (distribueert shares)
- **5.3** Rotatiestappen: systeeminitalisatie → downloaden nieuwe shares → rotatie-initialisatie → rotatie
- **5.4** Applicatie-eisen tijdens rotatie: offline tijdelijk, geen DB-connectie buiten rotatie, draait op dedicated host
- **5.5** Alle DEKs worden in 1 transactie met isolatie `repeatable read` herversleuteld met nieuwe KEK

### 6. Beveiligingseisen (aandachtspunten)
- **6.1** Geen logging van sessievariabelen (`application_name`)
- **6.2** Geen core dumps op OS
- **6.3** Geen debug logging op JBoss EAP
- **6.4** Exfiltratie voorkomen: KEK-applicatie communiceert alleen via gescheiden kanaal (niet HTTP, browser of SSH)

---

## NL GOV Standaarden (toegepast)

> Toegepast via de `logius-standaarden@overheid-plugins` plugin voor Claude Code.
> Plugin skills gebruikt: `standaarden:ls-iam`, `standaarden:ls-api`

### standaarden:ls-api — API Design Rules (ADR v2.1.0)

**Plugin:** `logius-standaarden@overheid-plugins` → skill `standaarden:ls-api`
**Bron:** [gitdocumentatie.logius.nl/publicatie/api/adr/2.1.0](https://gitdocumentatie.logius.nl/publicatie/api/adr/2.1.0/)
**Status:** Verplicht (pas-toe-of-leg-uit, Forum Standaardisatie)

| Regel | Toepassing in dit project | Bestand |
|-------|--------------------------|---------|
| Major versie in URI-pad | `/api/...` → `/v1/...` | alle controllers |
| Kebab-case padsegmenten | `poc1` → `poc-1`, `rotate-dek` → `dek-rotatie` | alle controllers |
| Operaties als `_` sub-resources | `_initialiseer`, `_reconstrueer` | `EnvelopeController`, `RotationController` |
| Zoekfilter als query-param op collectie | `GET /v1/poc-2?value=` (was `/search`) | `Poc2Controller`, `Poc3Controller` |
| `API-Version` response header | Toegevoegd op alle `/v1/` responses | `SecurityHeadersFilter` |
| Verplichte security headers (sectie 3.8) | `Cache-Control`, `CSP`, `HSTS`, `X-Content-Type-Options`, `X-Frame-Options` | `SecurityHeadersFilter` |
| `application/problem+json` (RFC 9457) | Globale foutafhandeling, `spring.mvc.problemdetails.enabled=true` | `ApiExceptionHandler`, `application.properties` |

### standaarden:ls-iam — OAuth 2.0 NL Profiel (v1.1.0) + OIDC NL GOV (v1.0.1)

**Plugin:** `logius-standaarden@overheid-plugins` → skill `standaarden:ls-iam`
**Bron:** [gitdocumentatie.logius.nl/publicatie/api/oauth](https://gitdocumentatie.logius.nl/publicatie/api/oauth/)
**Status:** Verplicht (pas-toe-of-leg-uit, Forum Standaardisatie)

| Regel | Toepassing in dit project | Bestand |
|-------|--------------------------|---------|
| Authorization Server met JWT access tokens (RFC 9068) | Spring Authorization Server op `http://localhost:8080` | `AuthorizationServerConfig` |
| `authorization_code` + PKCE verplicht voor public clients | `poc-web-client` met `requireProofKey(true)` | `AuthorizationServerConfig` |
| `client_credentials` voor machine-to-machine | `poc-service-client` | `AuthorizationServerConfig` |
| Access tokens via `Authorization: Bearer` header | Resource server JWT filter op alle `/v1/**` | `SecurityConfig` |
| Implicit grant verboden | Niet geconfigureerd | `AuthorizationServerConfig` |
| PKCE met `code_challenge_method=S256` | Standaard via Spring Authorization Server | `AuthorizationServerConfig` |
| Betrouwbaarheidsniveaus (eIDAS) | In-memory gebruiker als placeholder; in productie DigiD/eHerkenning | `AuthorizationServerConfig` |

**Demo gebruik:**
```
# Token ophalen (client_credentials):
POST http://localhost:8080/oauth2/token
Authorization: Basic cG9jLXNlcnZpY2UtY2xpZW50OnBvYy1zZXJ2aWNlLWdlaGVpbQ==
Content-Type: application/x-www-form-urlencoded
grant_type=client_credentials&scope=poc.lezen

# API aanroepen:
GET http://localhost:8080/v1/poc-1
Authorization: Bearer <access_token>
```

**Productie-afwijkingen (POC only):**
- `client_secret_basic` gebruikt i.p.v. `private_key_jwt` (verplicht per NL GOV OAuth)
- In-memory gebruiker i.p.v. DigiD/eHerkenning (verplicht per OIDC NL GOV)
- Demo login: `gebruiker` / `wachtwoord`

---

## Actieve POCs

### POC 1 — AES-GCM via AttributeConverter
- **Concept:** 3.1 — Niet-deterministisch versleuteld, geen zoeken mogelijk
- **Status:** done
- **Endpoints:** `POST /v1/poc-1`, `GET /v1/poc-1/{id}`, `GET /v1/poc-1`
- **Bestanden:** `poc1/AesGcmConverter.java`, `poc1/Poc1Entity.java`, `poc1/Poc1Repository.java`, `poc1/Poc1Controller.java`

### POC 2 — Deterministisch (AES-SIV concept) via AttributeConverter
- **Concept:** 3.2 — IV afgeleid van HMAC(sleutel, plaintext) zodat exact zoeken mogelijk is
- **Status:** done
- **Endpoints:** `POST /v1/poc-2`, `GET /v1/poc-2/{id}`, `GET /v1/poc-2?value=`
- **Bestanden:** `poc2/DeterministicConverter.java`, `poc2/Poc2Entity.java`, `poc2/Poc2Repository.java`, `poc2/Poc2Controller.java`

### POC 3 — AES-GCM + HMAC zoekindex
- **Concept:** 3.3 — AES-GCM encryptie + aparte HMAC-kolom als zoekindex
- **Status:** done
- **Endpoints:** `POST /v1/poc-3`, `GET /v1/poc-3/{id}`, `GET /v1/poc-3?value=`
- **Bestanden:** `poc3/Poc3Entity.java`, `poc3/Poc3Repository.java`, `poc3/Poc3Controller.java`

### POC 4 — @ColumnTransformer + H2 SQL-functies
- **Concept:** 3.4 — Encryptie op database-niveau via custom SQL-functies (simuleert pgcrypto)
- **Status:** done
- **Endpoints:** `POST /v1/poc-4`, `GET /v1/poc-4/{id}`, `GET /v1/poc-4`
- **Bestanden:** `poc4/H2EncryptFunctions.java`, `poc4/Poc4Entity.java`, `poc4/Poc4Repository.java`, `poc4/Poc4Controller.java`, `config/H2FunctionRegistrar.java`
- **Productie-equivalent:** vervang H2-functies door PostgreSQL `encrypt_string`/`decrypt_string` (pgcrypto)

### Envelope Encryption (DEK/KEK)
- **Concept:** 2.1 t/m 2.4 — DEKs per context, versleuteld met KEK, DEK-rotatie met REPEATABLE READ
- **Status:** done
- **Endpoints:** `POST /v1/envelope/dek/_initialiseer?context=`, `POST /v1/envelope`, `GET /v1/envelope/{id}`, `POST /v1/envelope/{context}/dek-rotatie`
- **Bestanden:** `envelope/DataEncryptionKey.java`, `envelope/DekRepository.java`, `envelope/EnvelopeEntity.java`, `envelope/EnvelopeRepository.java`, `envelope/KeyManagementService.java`, `envelope/EnvelopeController.java`

### POC 5 — Gecombineerde encryptie-strategieën
- **Concept:** 3.2 + 3.3 + 3.4 — Drie encryptie-aanpakken op één entity, afwegingen direct vergelijkbaar
- **Status:** done
- **Velden:**
  - `naam` — deterministisch AES-CBC (POC 2 stijl), exact zoeken via `?naam=`
  - `notitie` — AES-GCM + HMAC-index (POC 3 stijl), zoeken via `?notitie=`
  - `referentie` — @ColumnTransformer H2 SQL-functies (POC 4 stijl), geen zoekondersteuning
- **Endpoints:** `POST /v1/poc-5`, `GET /v1/poc-5`, `GET /v1/poc-5?naam=`, `GET /v1/poc-5?notitie=`, `GET /v1/poc-5/{id}`
- **Bestanden:** `poc5/Poc5Entity.java`, `poc5/Poc5Repository.java`, `poc5/Poc5Controller.java`
- **Hergebruikt:** `DeterministicConverter` (poc2), `AesGcmConverter` (poc1), `H2EncryptFunctions` + `H2FunctionRegistrar` (poc4)

### POC 6 — Dubbele encryptie (app + DB) met HMAC zoekindex
- **Concept:** 3.1 + 3.3 + 3.4 — AES-GCM (app-laag) + @ColumnTransformer (DB-laag) + HMAC-index per veld
- **Status:** done
- **Datastroom write:** `plaintext → AES-GCM (Java) → ENCRYPT_STRING (H2) → DB`
- **Datastroom read:** `DB → DECRYPT_STRING (H2) → AES-GCM decrypt (Java) → plaintext`
- **Zoeken:** HMAC van plaintext opgeslagen als aparte `_hmac` kolom; zoekterm wordt on-the-fly gehasht
- **Endpoints:** `POST /v1/poc-6`, `GET /v1/poc-6`, `GET /v1/poc-6?naam=`, `GET /v1/poc-6?notitie=`, `GET /v1/poc-6/{id}`
- **Bestanden:** `poc6/Poc6Entity.java`, `poc6/Poc6Repository.java`, `poc6/Poc6Controller.java`
- **Hergebruikt:** `AesGcmConverter` (poc1), `H2EncryptFunctions` + `H2FunctionRegistrar` (poc4)

### POC 7 — Row Level Security (RLS)
- **Concept:** PostgreSQL RLS gesimuleerd in H2 via Hibernate `@Filter`
- **Status:** done
- **Datastroom:** `X-Eigenaar-Id header → RlsContext (ThreadLocal) → Hibernate @Filter → WHERE eigenaar_id = :userId`
- **PostgreSQL-equivalent:** `SET LOCAL app.current_user_id = ?` + `CREATE POLICY ... USING (eigenaar_id = current_setting(...))`
- **Gotcha:** `EntityManager.find()` bypast Hibernate filters → `findByIdMetFilter()` via JPQL gebruikt in repository
- **Endpoints:** `POST /v1/poc-7`, `GET /v1/poc-7`, `GET /v1/poc-7/{id}`, `GET /v1/poc-7/_admin` (geen filter, BYPASSRLS equivalent)
- **Bestanden:** `poc7/RlsContext.java`, `poc7/RlsHandlerInterceptor.java`, `poc7/RlsConfig.java`, `poc7/Poc7Entity.java`, `poc7/Poc7Repository.java`, `poc7/Poc7Service.java`, `poc7/Poc7Controller.java`
- **Demo:** Seed-data voor 3 gebruikers; zonder header → `[]`; verkeerde user → 404; `/_admin` → alle 6 records

### KEK-rotatie — Shamir's Secret Sharing
- **Concept:** 5.1 t/m 5.5 — KEK splitsen in 5 shares (drempel 3) via GF(256) SSS
- **Status:** done
- **Endpoints:** `POST /v1/kek-rotatie/_initialiseer`, `POST /v1/kek-rotatie/_reconstrueer`
- **Bestanden:** `rotation/ShamirSecretSharing.java`, `rotation/RotationController.java`
- **Let op:** POC retourneert alle shares in één response — in productie distribueert de ceremoniemeester shares out-of-band (6.4)
