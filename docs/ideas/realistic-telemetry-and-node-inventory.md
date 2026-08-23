# Realistic Telemetry, Multi-API Noise & Node IP Inventory

## Problem Statement
> **How Might We** sostituire i nomi descrittivi dei container con IP di rete reali, generare traffico continuo con errori fisiologici su un set esteso di API crittografiche e centralizzare l'anagrafica IP nella tab "Inventario Nodi", per rendere l'attività di Threat Hunting e correlazione SIEM indistinguibile da un incidente reale?

## Recommended Direction
1. **Real IP Logging Engine**: Sostituzione dei campi `src_ip` nei log con gli indirizzi IP effettivi assegnati da Docker. L'analista non ha indizi visivi immediati sul ruolo dell'IP nei log grezzi.
2. **Enterprise Cryptographic REST API**: Estensione del container vittima con 5 endpoint applicativi (`/api/v1/auth/login`, `/api/v1/user/profile`, `/api/v1/crypto/encrypt`, `/api/v1/crypto/decrypt`, `/api/v1/token/verify`).
3. **Continuous Background Traffic with Jitter & Noise**: Client benigni implementati come daemon continui con intervalli stocastici e un tasso di errore fisiologico configurabile da UI (~2-4%) per simulare un carico di rete reale.
4. **Node Asset Inventory (Ex Gestione Docker)**: Tab dedicata alla mappatura IP $\leftrightarrow$ Container, risoluzione host, porte e stato di salute, eliminando i controlli di traffico duplicati.

## Key Assumptions Validated
- [x] **Docker IP Resolution**: Il server vittima legge correttamente l'IP del client tramite `request.remote_addr` o `X-Forwarded-For`.
- [x] **Zero False Positives con Errori Fisiologici**: Gli errori normali dei client benigni (~3%) non superano la soglia del WAF (soglia minima 70-80% su `/decrypt`).
- [x] **Configurabilità UI**: L'utente può regolare via modal la percentuale di errori e la modalità continua per i benigni, nonché segreto e delay per l'attaccante.

## MVP Scope
- **Victim App (`victim/app.py`)**: Aggiunta rotte `/api/v1/auth/login`, `/api/v1/user/profile`, `/api/v1/crypto/encrypt`, `/api/v1/crypto/decrypt`, `/api/v1/token/verify` con logging unificato per IP.
- **Benign Clients (`benign/benign_client.py`)**: Modalità daemon continua con sleep dinamico (100-600ms), ciclo multi-API e iniezione casuale di anomalie fisiologiche (bad token, invalid credentials).
- **Attacker (`attacker/attack.py`)**: Utilizzo dell'IP effettivo del container per l'attacco su AES-CBC `/decrypt`.
- **UI Dashboard (`soc/dashboard.py`)**:
  - Restyling della tab in **"📋 Inventario Nodi & IP"** con tabella di associazione IP $\leftrightarrow$ Nome Container, porte e stato.
  - Modali interattivi `modal-benign` e `modal-attacker` per configurazione dinamica di parametri e rumore.

## Not Doing (and Why)
- **Generatore di traffico packet-level (Scapy / Raw PCAP)**: Aumenterebbe la complessità di permessi `root` / `NET_ADMIN` in Docker. Il client HTTP asincrono a livello L7 è pulito, portabile e spiegabile al docente.
- **DDoS Volumetrico multi-Gbit**: L'obiettivo didattico è un attacco applicativo L7 mirato a una falla crittografica (Padding Oracle), non l'esaurimento di banda.
