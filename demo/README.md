# Secure Token Service (STS) — Local Demo

Setup minimale per preparare il database ed eseguire localmente il **Secure Token Service (`sts`)** per la demo.

## 1. Preparazione Prerequisiti e Migrazione DB

Esegui lo script di preparazione dalla root del repository:

```bash
./demo/prepare-demo.sh
```

*(Passa `--build` per forzare la ricompilazione del binario `./bin/sts`).*

**Cosa fa lo script:**
* Compila `./bin/sts` se non è già presente (o se viene passato `--build`).
* Verifica che il container Valkey (`localhost:6379`) sia attivo e lo avvia tramite Docker Compose se necessario.
* Attende che PostgreSQL su `localhost:5433` (container `authz-postgres`, database `sts`) sia pronto (`pg_isready`) e verifica che il database `sts` esista.
* Carica le variabili d'ambiente della demo (`demo/env.sh`) ed esegue le migrazioni del database con:
  ```bash
  sts migrate
  ```

## 2. Avvio dell'Applicazione

Una volta completata la preparazione, avvia il servizio con:

```bash
./demo/run-app.sh
```

**Cosa aspettarsi:**
* Carica l'environment configurato in `demo/env.sh` ed esegue `sts serve`:
  * **HTTP server (`0.0.0.0:8080`)**: espone gli endpoint di autenticazione OIDC (`/auth/login`, `/auth/callback`, `/auth/logout`) e gli healthcheck.
  * **gRPC server (`0.0.0.0:9090`)**: espone le API gRPC per la validazione sessioni e lo scambio token.
