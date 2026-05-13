# Security Demo

Spring Boot sandbox voor security-implementaties. Twee actieve demo's:

| | Demo |
|---|---|
| **POC 6** | Dubbele encryptie (app-laag + DB-laag) met HMAC-zoekindex |
| **POC 7** | Row Level Security via Hibernate `@Filter` (simuleert PostgreSQL RLS) |

## Stack

- Java 25 / Spring Boot 4.x
- Spring Security + Spring Authorization Server (OAuth 2.0 / OIDC)
- Spring Data JPA + Hibernate
- H2 in-memory (simuleert PostgreSQL)

## Opstarten

```bash
./mvnw spring-boot:run
```

App beschikbaar op `http://localhost:8080`.  
H2 console: `http://localhost:8080/h2-console` (JDBC URL: `jdbc:h2:mem:securitydb`, geen wachtwoord).

---

## POC 6 — Dubbele encryptie met HMAC-zoekindex

### Concept

Elk vertrouwelijk veld wordt op **twee lagen** versleuteld:

1. **Java-laag** — `AesGcmConverter` (JPA `AttributeConverter`, AES-GCM, willekeurige IV per opslag)
2. **Database-laag** — `ENCRYPT_STRING` via Hibernate `@ColumnTransformer` (simuleert PostgreSQL `pgcrypto`)

Zoeken is mogelijk via een aparte **HMAC-SHA256-kolom** per veld. De zoekterm wordt on-the-fly gehasht en vergeleken met de opgeslagen index — de plaintext verschijnt nooit in een `WHERE`-clause.

```
Write:  plaintext
         → AES-GCM encrypt   (Java / AesGcmConverter)
         → ENCRYPT_STRING     (H2 SQL-functie / H2EncryptFunctions)
         → opslag in DB

Read:   DB
         → DECRYPT_STRING     (H2 SQL-functie)
         → AES-GCM decrypt    (Java / AesGcmConverter)
         → plaintext

Zoeken: hmacBase64(zoekterm) == naam_hmac  →  WHERE naam_hmac = ?
```

### Endpoints

| Methode | Pad | Beschrijving |
|---------|-----|--------------|
| `POST` | `/v1/poc-6` | Sla een versleuteld record op |
| `GET` | `/v1/poc-6` | Alle records |
| `GET` | `/v1/poc-6?naam=<waarde>` | Zoeken op naam via HMAC-index |
| `GET` | `/v1/poc-6?notitie=<waarde>` | Zoeken op notitie via HMAC-index |
| `GET` | `/v1/poc-6/{id}` | Enkel record |
| `GET` | `/v1/poc-6/_perf?operatie=...` | Performance meting (zie hieronder) |

**`_perf` operaties:** `lijst` · `zoek-naam&q=<waarde>` · `zoek-notitie&q=<waarde>` · `enkel&q=<id>`

### Voorbeelden

```bash
# Record aanmaken
curl -s -X POST http://localhost:8080/v1/poc-6 \
  -H "Content-Type: application/json" \
  -d '{"naam":"Emma de Vries","notitie":"Vertrouwelijk dossier nummer 1","openbaar":"record-1"}' | jq

# Zoeken op naam (HMAC-index, ~100 resultaten uit 10.000 records)
curl -s "http://localhost:8080/v1/poc-6?naam=Emma+de+Vries" | jq 'length'

# Performance meting: zoeken op naam
curl -s "http://localhost:8080/v1/poc-6/_perf?operatie=zoek-naam&q=Emma+de+Vries" | jq
# → {"operatie":"zoek-naam","aantalResultaten":100,"totaalRecords":10000,"duurMs":12}
```

### Seed-data

Bij opstarten worden automatisch **10.000 records** aangemaakt (100 unieke namen × 100 unieke notities). Zoeken op een naam geeft daardoor ~100 resultaten — realistisch voor een performance-meting.

---

## POC 7 — Row Level Security

### Concept

Simulatie van PostgreSQL **Row Level Security** via Hibernate `@Filter`. Elke rij heeft een `eigenaar_id`; het filter zorgt dat gebruikers alleen hun eigen rijen zien.

De eigenaar wordt doorgegeven via de `X-Eigenaar-Id` header (simuleert in productie de JWT `sub`-claim of een PostgreSQL sessievariabele).

```
Request  →  RlsHandlerInterceptor leest X-Eigenaar-Id header
         →  RlsContext.set(eigenaarId)           (ThreadLocal)
         →  DemoService.activeerRlsFilter()      (Hibernate Session)
         →  WHERE eigenaar_id = :huidigeEigenaarId   (automatisch op elke query)
         →  Cleanup: RlsContext.clear()          (na afloop request)
```

**Belangrijke gotcha:** `EntityManager.find()` bypast Hibernate-filters. De repository gebruikt daarom een JPQL-query voor ID-lookups (`findByIdMetFilter`).

### PostgreSQL-equivalent

```sql
-- Eenmalig aanmaken
CREATE POLICY rls_eigen_data ON poc7
  USING (eigenaar_id = current_setting('app.current_user_id'));
ALTER TABLE poc7 ENABLE ROW LEVEL SECURITY;

-- Per request (Spring-datasource of connection pool)
SET LOCAL app.current_user_id = 'gebruiker-1';
SELECT * FROM poc7;  -- ziet alleen eigen rijen
```

### Endpoints

| Methode | Pad | Header vereist | Beschrijving |
|---------|-----|----------------|--------------|
| `POST` | `/v1/poc-7` | `X-Eigenaar-Id` | Record aanmaken |
| `GET` | `/v1/poc-7` | `X-Eigenaar-Id` | Eigen records (RLS actief) |
| `GET` | `/v1/poc-7/{id}` | `X-Eigenaar-Id` | Enkel record — **404** als niet van jou |
| `GET` | `/v1/poc-7/_admin` | — | Alle records, geen filter (BYPASSRLS) |

### Voorbeelden

```bash
# Record aanmaken als gebruiker-1
curl -s -X POST http://localhost:8080/v1/poc-7 \
  -H "Content-Type: application/json" \
  -H "X-Eigenaar-Id: gebruiker-1" \
  -d '{"inhoud":"geheime tekst","openbaar":"zichtbaar"}' | jq

# Eigen records ophalen
curl -s http://localhost:8080/v1/poc-7 -H "X-Eigenaar-Id: gebruiker-1" | jq 'length'
# → 3

# Zonder header → lege lijst (geen eigenaar-context)
curl -s http://localhost:8080/v1/poc-7 | jq 'length'
# → 0

# Record van andere eigenaar → 404 (onthult niet of het record bestaat)
curl -s -o /dev/null -w "%{http_code}" \
  -H "X-Eigenaar-Id: gebruiker-2" http://localhost:8080/v1/poc-7/1
# → 404

# Admin: alle records zonder filter
curl -s http://localhost:8080/v1/poc-7/_admin | jq 'length'
# → 6
```

### Seed-data

| Eigenaar | Records |
|----------|---------|
| `gebruiker-1` | 3 |
| `gebruiker-2` | 2 |
| `gebruiker-3` | 1 |

---

## OAuth 2.0 (Spring Authorization Server)

De app bevat een Authorization Server conform het NL GOV OAuth 2.0 profiel. De endpoints zijn beschikbaar maar **niet afgedwongen** in deze demo — alle `/v1/**` routes zijn bereikbaar zonder token.

```bash
# Token ophalen (client_credentials)
curl -s -X POST http://localhost:8080/oauth2/token \
  -u "poc-service-client:poc-service-geheim" \
  -d "grant_type=client_credentials&scope=poc.lezen" | jq .access_token

# API aanroepen met token
curl -s http://localhost:8080/v1/poc-6 \
  -H "Authorization: Bearer <token>" | jq length
```

| Client | Grant type | Gebruik |
|--------|-----------|---------|
| `poc-web-client` | `authorization_code` + PKCE | Browser / eindgebruiker |
| `poc-service-client` | `client_credentials` | Machine-to-machine |

Demo login voor `authorization_code` flow: `gebruiker` / `wachtwoord`

---

## Projectstructuur

```
src/main/java/com/demo/security/
├── controller/
│   ├── EncryptionController.java     POC 6 endpoints (/v1/poc-6/**)
│   └── RlsController.java            POC 7 endpoints (/v1/poc-7/**)
├── service/
│   ├── EncryptionService.java        business logic + HMAC-berekening voor POC 6
│   └── RlsService.java               RLS-filter activering + queries voor POC 7
├── domain/
│   ├── EncryptedRecord.java          entity voor POC 6 (tabel: poc6)
│   └── RlsRecord.java                entity voor POC 7 (tabel: poc7)
├── repository/
│   ├── EncryptedRecordRepository.java
│   └── RlsRecordRepository.java
├── rls/
│   ├── RlsContext.java               ThreadLocal voor eigenaar-id (simuleert sessievariabele)
│   ├── RlsHandlerInterceptor.java    leest X-Eigenaar-Id header en zet RlsContext
│   └── RlsConfig.java                registreert interceptor op /v1/poc-7/**
├── crypto/
│   ├── AesGcmConverter.java          JPA AttributeConverter: AES-GCM
│   ├── H2EncryptFunctions.java       H2 SQL-functies: ENCRYPT_STRING / DECRYPT_STRING
│   └── CryptoUtil.java               AES-GCM + HMAC utilities
├── seeder/
│   ├── EncryptedRecordSeeder.java    10.000 testrecords bij opstarten
│   └── RlsRecordSeeder.java          6 testrecords voor 3 gebruikers
├── audit/
│   └── AuditService.java             GDPR/AVG auditlogging (apart logbestand)
└── config/
    ├── AuthorizationServerConfig.java   OAuth 2.0 Authorization Server
    ├── SecurityConfig.java              resource server (JWT Bearer)
    ├── H2FunctionRegistrar.java         registreert H2 SQL-functies bij opstarten
    ├── SecurityHeadersFilter.java       NL GOV security headers (ADR §3.8)
    ├── RequestTimingFilter.java         logt request-duur op /v1/**
    └── ApiExceptionHandler.java         RFC 9457 application/problem+json
```

Auditlogs worden geschreven naar `logs/audit.log` (90 dagen rotatie).
