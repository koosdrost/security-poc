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

## Actieve POCs

### POC 1 — AES-GCM via AttributeConverter
- **Concept:** 3.1 — Niet-deterministisch versleuteld, geen zoeken mogelijk
- **Status:** done
- **Endpoints:** `POST /api/poc1`, `GET /api/poc1/{id}`, `GET /api/poc1`
- **Bestanden:** `poc1/AesGcmConverter.java`, `poc1/Poc1Entity.java`, `poc1/Poc1Repository.java`, `poc1/Poc1Controller.java`

### POC 2 — Deterministisch (AES-SIV concept) via AttributeConverter
- **Concept:** 3.2 — IV afgeleid van HMAC(sleutel, plaintext) zodat exact zoeken mogelijk is
- **Status:** done
- **Endpoints:** `POST /api/poc2`, `GET /api/poc2/{id}`, `GET /api/poc2/search?value=`
- **Bestanden:** `poc2/DeterministicConverter.java`, `poc2/Poc2Entity.java`, `poc2/Poc2Repository.java`, `poc2/Poc2Controller.java`

### POC 3 — AES-GCM + HMAC zoekindex
- **Concept:** 3.3 — AES-GCM encryptie + aparte HMAC-kolom als zoekindex
- **Status:** done
- **Endpoints:** `POST /api/poc3`, `GET /api/poc3/{id}`, `GET /api/poc3/search?value=`
- **Bestanden:** `poc3/Poc3Entity.java`, `poc3/Poc3Repository.java`, `poc3/Poc3Controller.java`

### POC 4 — @ColumnTransformer + H2 SQL-functies
- **Concept:** 3.4 — Encryptie op database-niveau via custom SQL-functies (simuleert pgcrypto)
- **Status:** done
- **Endpoints:** `POST /api/poc4`, `GET /api/poc4/{id}`, `GET /api/poc4`
- **Bestanden:** `poc4/H2EncryptFunctions.java`, `poc4/Poc4Entity.java`, `poc4/Poc4Repository.java`, `poc4/Poc4Controller.java`, `config/H2FunctionRegistrar.java`
- **Productie-equivalent:** vervang H2-functies door PostgreSQL `encrypt_string`/`decrypt_string` (pgcrypto)

### Envelope Encryption (DEK/KEK)
- **Concept:** 2.1 t/m 2.4 — DEKs per context, versleuteld met KEK, DEK-rotatie met REPEATABLE READ
- **Status:** done
- **Endpoints:** `POST /api/envelope/dek/init?context=`, `POST /api/envelope`, `GET /api/envelope/{id}`, `POST /api/envelope/{context}/rotate-dek`
- **Bestanden:** `envelope/DataEncryptionKey.java`, `envelope/DekRepository.java`, `envelope/EnvelopeEntity.java`, `envelope/EnvelopeRepository.java`, `envelope/KeyManagementService.java`, `envelope/EnvelopeController.java`

### KEK-rotatie — Shamir's Secret Sharing
- **Concept:** 5.1 t/m 5.5 — KEK splitsen in 5 shares (drempel 3) via GF(256) SSS
- **Status:** done
- **Endpoints:** `POST /api/rotation/init`, `POST /api/rotation/reconstruct`
- **Bestanden:** `rotation/ShamirSecretSharing.java`, `rotation/RotationController.java`
- **Let op:** POC retourneert alle shares in één response — in productie distribueert de ceremoniemeester shares out-of-band (6.4)
