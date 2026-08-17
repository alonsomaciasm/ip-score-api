# IP Reputation Score API (Enterprise / PII Zero & Privacy by Design)

Una API de grado producción empresarial desarrollada en Python moderno (FastAPI, Pydantic v2, Redis, Structlog) para la evaluación del score de reputación y riesgo de direcciones IPv4 y IPv6.

Diseñada bajo los principios de **Security by Design**, **Privacy by Design** y **PII Zero real**.

---

## 🔒 Principios Fundamentales Empresariales

### 1. PII Zero Real
- **Sin Almacenamiento de IPs**: La dirección IP nunca se guarda en disco, bases de datos o sistemas de logs.
- **Caché Anónima**: Las claves de Redis utilizan exclusivamente un hash SHA-256 rotativo con salt secreta (`ip_score:<sha256(salt + ip)>`).
- **Logs Sanitizados**: Implementación del procesador `PIIScrubber` en `structlog` que redacta automáticamente cualquier IPv4/IPv6 de los eventos de log.
- **Geolocalización Limitada**: Sin procesamiento de geolocalización precisa (ciudad, código postal, latitud/longitud).

### 2. Alta Disponibilidad & Resiliencia Offline-First
- **Carga Inmediata desde Disco (`data/feeds/`)**: Al iniciar, la API carga primero el caché local persistido en disco para disponibilidad instantánea (p95 < 10ms), incluso en entornos aislados o sin internet.
- **Actualizaciones en Segundo Plano**: Descarga periódica asíncrona mediante `APScheduler` de 16 fuentes de inteligencia: nodos Tor Exit, Fullbogons (Team Cymru), Botnet C2 (Abuse.ch Feodo/ThreatFox), Active Phishing (OpenPhish/PhishTank/IPsum), datacenters e infraestructura cloud de **AWS, GCP, Azure, Oracle Cloud (OCI), DigitalOcean, Alibaba Cloud (Aliyun), Tencent Cloud, Vultr y FireHOL Datacenter**, CDN Egress (Cloudflare/Fastly), Spamhaus DROP, FireHOL L1 y **Apple Private Relay**.

### 3. Observabilidad & Trazabilidad Nivel Enterprise
- **Métricas Prometheus (`GET /api/v1/metrics`)**: Exportación de métricas de negocio y rendimiento sin PII (`ip_score_requests_total`, `ip_score_feed_elements_total`).
- **Visor de Trazas & Eventos PII-Zero (`GET /dashboard/stats`)**: Endpoint y consola SIEM interactiva en el Dashboard para auditar en vivo la distribución de riesgo (`low`, `medium`, `high`, `critical`), tasa de evaluaciones y flujo anónimo de solicitudes con latencia en ms.
- **Sanitización de Logs PII Zero**: Scrubber en el pipeline de `structlog` que redacta automáticamente cualquier dirección IP (`[REDACTED_IP]`) antes de escribir a stdout o disco (`data/logs/ip_score.log`).
- **Correlation ID (`X-Request-ID`)**: Trazabilidad completa de peticiones en entornos de microservicios.
- **Manejo de Errores RFC 7807**: Respuestas de error estandarizadas con timestamp e ID de correlación sin exponer stack traces.

---

## 🛠️ Stack Tecnológico

- **Framework**: FastAPI (Async)
- **ASGI Server**: Uvicorn / Hypercorn
- **Validación y Serialización**: Pydantic v2 + `ipaddress` (stdlib)
- **Networking & Matching**: `netaddr` (IPSet in-memory) + FCrDNS (Async Reverse DNS)
- **Caché & Velocidad**: Redis (claves SHA-256 + Salt + HyperLogLog /24 & /48 Subnet Anomaly Tracker)
- **Bases de Datos de IP**: MaxMind GeoLite2 ASN (`maxminddb`) + 9 Feeds locales verificados con SHA-256
- **Observabilidad**: Structlog (PII Zero Scrubber) + Prometheus Client
- **Pruebas**: Pytest + pytest-asyncio + HTTPX

---

## ⚙️ Variables de Entorno y Configuración (`.env`)

Toda la API está parametrizada mediante Pydantic BaseSettings en [`app/config.py`](app/config.py) y se configura mediante [`.env`](.env):

| Variable de Entorno | Tipo | Valor Predeterminado | Descripción |
| :--- | :--- | :--- | :--- |
| `ENVIRONMENT` | String | `production` | Modo de ejecución (`development`, `staging`, `production`). |
| `DEBUG` | Boolean | `false` | Habilita logs detallados e inspección de desarrollo. |
| `SALT_SECRET` | String | *Secuencia 32+ chars* | Clave secreta para hashes SHA-256 rotativos diarios de Redis (PII Zero). |
| `JWT_SECRET` | String | *Secuencia 32+ bytes* | Clave secreta o pública para verificar tokens Bearer JWT. |
| `JWT_ALGORITHM` | String | `HS256` | Algoritmo de firma de tokens JWT (`HS256`, `RS256`, `EdDSA`). |
| `API_KEYS` | JSON String | *Diccionario predeterminado* | Mapeo JSON de API Keys/Hashes a sus scopes permitidos. |
| `ALLOW_PRIVATE_IPS_FOR_TESTING` | Boolean | `false` | Permite evaluar IPs privadas (RFC 1918) sólo para pruebas locales. |
| `CACHE_ENABLED` | Boolean | `true` | Interruptor maestro del motor de caché L1 (RAM) y L2 (Redis). |
| `REDIS_URL` | String | `redis://redis:6379/0` | URL de conexión al servicio Redis L2. |
| `CACHE_TTL_SECONDS` | Integer | `300` | Tiempo de vida de resultados en caché (5 minutos). |
| `L1_CACHE_MAX_SIZE` | Integer | `10000` | Límite de ítems en el caché LRU en memoria RAM (respuesta `< 0.3 ms`). |
| `L1_CACHE_TTL_SECONDS` | Integer | `300` | Expiración de entradas en el caché L1 en RAM. |
| `FCRDNS_TIMEOUT_SECONDS` | Float | `1.0` | Timeout estricto de socket para consultas DNS inversas (FCrDNS). |
| `RATE_LIMIT_PER_MINUTE` | Integer | `100` | Límite de peticiones por minuto por API Key / Token. |
| `BATCH_MAX_SIZE` | Integer | `50` | Límite máximo de IPs por lote en `POST /api/v1/score/batch`. |
| `FEED_UPDATE_INTERVAL_HOURS` | Integer | `12` | Frecuencia de actualización en segundo plano de los 10 feeds en disco. |

---

## 📊 Modelo de Scoring

$$\text{Risk Score} = \min\left(100, \sum \text{Puntos por Señal}\right)$$

| Señal | Incremento | Flag |
| :--- | :--- | :--- |
| **Botnet C2 Server (Abuse.ch)** | +100 | `is_abuse_listed: true` |
| **Bogon Subnet (Team Cymru)** | +95 | `is_proxy: true` |
| **Tor Exit Node** | +90 | `is_tor: true`, `is_proxy: true` |
| **Open / Known Proxy** | +75 | `is_proxy: true` |
| **Listas de Abuso (Spamhaus/FireHOL)** | +70 | `is_abuse_listed: true` |
| **VPN Comercial** | +50 | `is_vpn: true` |
| **Cloud / Datacenter ASN** | +35 | `is_datacenter: true` |
| **Anomalía de Velocidad por Subred** | +30 | `is_proxy: true` |
| **Apple Private Relay** | +15 | `is_icloud_relay: true`, `is_vpn: true` |
| **CDN Edge Egress (Cloudflare/Fastly)** | +10 | `is_cdn_egress: true` |
| **Verified Search Bot (FCrDNS)** | Forzado 0 | `network_type: "search_engine_bot"` |
| **Red Educativa / Gubernamental** | Mitigación | `network_type: "education_government"` |
| **Red Residencial / Mobile** | +0 | `is_residential` / `is_mobile` |

### Niveles y Recomendaciones

- **0 – 29** (`low`): `allow` (Permitir)
- **30 – 59** (`medium`): `flag` (Monitorear / aplicar rate limit)
- **60 – 84** (`high`): `challenge` (Requerir CAPTCHA / 2FA)
- **85 – 100** (`critical`): `block` (Bloquear transacción o registro)

---

## 🚀 Endpoints Principales

### 1. Evaluación Individual (`POST /api/v1/score`)

**Con API Key (`X-API-Key`):**
```bash
curl -X POST "http://localhost:8000/api/v1/score" \
     -H "Content-Type: application/json" \
     -H "X-API-Key: sk_test_1234567890abcdef" \
     -d '{"ip": "185.220.101.5"}'
```

**Con Bearer JWT Token (`Authorization: Bearer <token>`):**
```bash
curl -X POST "http://localhost:8000/api/v1/score" \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer eyJhbGciOiJIUzI1Ni..." \
     -d '{"ip": "185.220.101.5"}'
```

### 2. Evaluación Masiva por Lote (`POST /api/v1/score/batch`)

```bash
curl -X POST "http://localhost:8000/api/v1/score/batch" \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer eyJhbGciOiJIUzI1Ni..." \
     -d '{"ips": ["185.220.101.5", "8.8.8.8", "17.248.10.5"]}'
```

### 3. Métricas Prometheus (`GET /api/v1/metrics`)

```bash
curl -H "X-API-Key: sk_test_1234567890abcdef" http://localhost:8000/api/v1/metrics
```

### 4. Exportación Streaming CSV de Ciberinteligencia (`GET /api/v1/export`)

Permite descargar en flujo continuo los listados consolidados de IPs maliciosas, nodos Tor Exit, servidores Botnet C2, rangos de Datacenters y Phishing en formato CSV optimizado con cabecera UTF-8 BOM para directa ingesta en sistemas SIEM (Splunk, Elastic) o Excel:

```bash
# Exportar todos los feeds
curl -H "X-API-Key: sk_test_1234567890abcdef" "http://localhost:8000/api/v1/export?feed_type=all" -o ip_reputation_feeds.csv

# Exportar únicamente nodos Tor
curl -H "X-API-Key: sk_test_1234567890abcdef" "http://localhost:8000/api/v1/export?feed_type=tor" -o tor_nodes.csv
```

### 5. Componente Frontend Autónomo (`/static/ip-score-widget.js`)

Incrustable en cualquier sitio o aplicación web mediante una sola etiqueta `<script>` para protección anti-fraude automática y detección de riesgo previa al envío de formularios sensibles (login, registro, pagos):

```html
<script src="http://localhost:8000/static/ip-score-widget.js" 
        data-api-url="http://localhost:8000" 
        data-api-key="sk_test_1234567890abcdef"
        data-auto-protect-forms="true"
        data-block-threshold="60">
</script>
```

---

## 🤖 Interoperabilidad con Agentes de IA (Model Context Protocol - MCP)

La API cuenta con un servidor nativo del protocolo **Model Context Protocol (MCP)** en [`scripts/mcp_server.py`](scripts/mcp_server.py). Esto permite a **Agentes de IA Autónomos** (Claude Desktop, Antigravity IDE, Cursor, LangChain, CrewAI, AutoGen) evaluar el riesgo de IPs directamente en lenguaje natural y sin alucinaciones.

### Herramientas MCP Expuestas (`tools`)

1. **`evaluate_ip_risk(ip: str, allow_private: bool = False)`**:
   - Evalúa el riesgo (0-100), nivel (`low`, `medium`, `high`, `critical`), recomendación de acción (`allow`, `flag`, `challenge`, `block`), banderas de amenazas (Tor, VPN, Proxy, Botnet C2, Abuse lists, Cloud Datacenter, Apple Private Relay, CDN egress) y FCrDNS/ASN.
2. **`evaluate_batch_ip_risks(ips: list[str], allow_private: bool = False)`**:
   - Evaluación masiva de riesgo para hasta 50 direcciones IP en una sola llamada.
3. **`get_ip_score_metrics_summary()`**:
   - Resume el estado del motor, capacidad de las 16 fuentes de ciberinteligencia cargadas y reglas de scoring.

### Configuración en Clientes de IA (ej. Claude Desktop / Antigravity IDE)

Agrega la siguiente configuración al archivo de settings MCP de tu cliente (`claude_desktop_config.json` / `.gemini/config/mcp_config.json`):

```json
{
  "mcpServers": {
    "ip-score-api": {
      "command": "python3",
      "args": [
        "/home/alonso/Proyectos/ip-score-api/scripts/mcp_server.py"
      ],
      "env": {
        "PYTHONPATH": "/home/alonso/Proyectos/ip-score-api"
      }
    }
  }
}
```

---

## 🧪 Ejecución de Tests

```bash
.venv/bin/python3 -m pytest -v
```

---

## ⚔️ Comparativa con Soluciones Comerciales (Estado del Arte)

| Criterio de Comparación | **IP-Score API (Este Proyecto)** | **IPQualityScore (IPQS)** | **MaxMind minFraud** | **AbuseIPDB** | **GreyNoise** |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Modelo de Privacidad** | 🟢 **PII-Zero Criptográfico** (Cero almacenamiento de IP, Salt rotativa) | 🔴 Almacena IPs de clientes para perfilamiento comercial | 🔴 Almacena datos transaccionales e IP | 🟡 Almacena reportes comunitarios con IPs | 🔴 Almacena trazas completas de scanners |
| **Arquitectura de Despliegue** | 🟢 **100% Self-Hosted / On-Premise** (Sin dependencia Cloud) | 🔴 SaaS de Pago por llamada (Cloud Propietario) | 🔴 SaaS de Pago por llamada (Cloud Propietario) | 🟡 SaaS Freemium | 🔴 SaaS Comercial |
| **Latencia p50** | 🟢 **< 10 ms** (In-Memory IPSet + Redis Local) | 🟡 ~50 – 150 ms (Llamada HTTP remota) | 🟡 ~50 – 120 ms (Llamada HTTP remota) | 🔴 ~100 – 300 ms (Lookup en API externa) | 🟡 ~60 – 150 ms (Llamada HTTP remota) |
| **Explicabilidad del Score** | 🟢 **Score Explicable 0-100** (Transparencia en `signals_used`) | 🔴 Algoritmo en Caja Negra (*Black Box ML*) | 🔴 Algoritmo en Caja Negra (*Black Box ML*) | 🟡 Basado sólo en número de reportes | 🟡 Categorías (`benign`/`malicious`) |
| **Fuentes de Inteligencia** | 🟢 **16 Feeds Integrados** (AWS, GCP, Azure, OCI, DigitalOcean, Aliyun, Tencent, Vultr, FireHOL Datacenter, Tor, Bogons, C2, Phishing, Abuse, FCrDNS, Apple Relay) | 🟡 Feeds Propietarios Cerrados | 🟡 Transacciones Comerciales | 🟡 Reportes Comunitarios | 🟡 Sensores Honeypot |
| **Cumplimiento Normativo** | 🟢 **GDPR Art. 5 (Exento de consentimiento PII)** | 🟡 Requiere aviso de privacidad y consentimiento de transferencia | 🟡 Requiere consentimiento explícito de transferencia | 🟡 Público / Reportes de abuso | 🟡 Datos de tráfico de red |

---

## 📚 Documentación Técnica Detallada

Para una especificación formal y completa de la arquitectura y contratos, consulta la carpeta [`docs/`](docs/):

1. 📄 **[Contrato Oficial de API (`docs/api_contract.md`)](docs/api_contract.md)**:
   - Especificación detallada OpenAPI 3.0 de endpoints, parámetros, respuestas y esquemas JSON.

2. 🛡️ **[Arquitectura, Seguridad & Cumplimiento (`docs/architecture_and_security.md`)](docs/architecture_and_security.md)**:
   - Diagramas de flujo de datos en Mermaid, mecanismo criptográfico PII Zero con salt rotativa diaria, endurecimiento en Docker y guía de cumplimiento normativo (GDPR & LFPDPPP México).

---

## 🛡️ Cumplimiento (GDPR + LFPDPPP México)

1. **No Requiere Almacenamiento de Datos Personales**: Al aplicar PII Zero y destruir la dirección IP en memoria inmediatamente después de responder, no se constituyen ficheros de datos personales persistentes.
2. **Minimización Estricta**: Procesamiento strictly necesario durante la ventana de decisión.
3. **Auditable y Explicable**: Cumple con las exigencias de transparencia al justificar cada nivel de riesgo a través del campo `signals_used`.

---

## ⚖️ Licencias, Atribución y Cumplimiento Legal

```text
MIT License

Copyright (c) 2026 MC. José Alonso Macías Montoya / Universidad Politécnica de Chiapas

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice, this permission notice, and the following conditions
shall be included in all copies or substantial portions of the Software:

1. ATRIBUCIÓN DE AUTORÍA: En caso de utilizar, modificar, publicar o redistribuir 
   este código o API en otros proyectos académicos, comerciales o de software libre, 
   se solicita mantener la debida mención o atribución de autoría al MC. José Alonso 
   Macías Montoya y a la Universidad Politécnica de Chiapas.

2. CUMPLIMIENTO LFPDPPP (MÉXICO) Y PROTECCIÓN DE DATOS: Esta API ha sido diseñada 
   bajo arquitectura Stateless (Sin Persistencia) y PII-Zero. Todo el procesamiento de datos 
   se efectúa en memoria volátil únicamente durante el ciclo de solicitud/respuesta. 
   Cualquier persona física o moral que despliegue o aloje esta API hacia terceros 
   asume de forma exclusiva el carácter de "Responsable del Tratamiento de Datos Personales" 
   en apego a la LFPDPPP y disposiciones del INAI.

3. DESLINDE DE RESPONSABILIDAD: El autor (MC. José Alonso Macías Montoya) y la 
   Universidad Politécnica de Chiapas quedan completamente liberados de cualquier 
   responsabilidad legal, civil, administrativa, penal o comercial derivada del uso, 
   mal uso, almacenamiento indebido o tratamiento no autorizado de información que 
   realicen terceros utilizando esta herramienta.

4. ATRIBUCIÓN Y LICENCIAS DE FUENTES DE INTELIGENCIA Y RECURSOS DE TERCEROS:
   Esta aplicación integra y/o consume los siguientes conjuntos de datos de ciberinteligencia 
   y componentes de software de código abierto bajo sus respectivas licencias permisivas:

   a) Tor Project Exit List (Tor Exits):
      - Mantenedor: The Tor Project, Inc.
      - Enlace: https://check.torproject.org/torbulkexitlist
      - Licencia: Dominio Público / BSD License.
      - Uso: Identificación in-memory de nodos de salida oficiales de la red Tor.

   b) Team Cymru Fullbogons List:
      - Mantenedor: Team Cymru.
      - Enlace: https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt
      - Licencia: Términos Abiertos de Ciberdefensa Operacional.
      - Uso: Filtrado in-memory de subredes no asignadas por IANA (Spoofing).

   c) Abuse.ch Botnet C2 (Feodo Tracker & ThreatFox):
      - Mantenedor: abuse.ch.
      - Enlace: https://feodotracker.abuse.ch/ & https://threatfox.abuse.ch/
      - Licencia: Creative Commons CC0 1.0 Universal (CC0 1.0) Public Domain Dedication.
      - Uso: Identificación in-memory de servidores de Comando y Control (C2) de Botnets activos.

   d) OpenPhish Community Feed & PhishTank (Cisco Talos):
      - Mantenedor: OpenPhish & PhishTank / Cisco Talos.
      - Enlace: https://openphish.com/ & https://www.phishtank.com/
      - Licencia: Licencia Abierta para Ciberdefensa y Prevención de Fraude.
      - Uso: Detección in-memory de hosts y servidores albergando sitios de phishing activos.

   e) IPsum Aggregated Threat Feed:
      - Mantenedor: Stamparm.
      - Enlace: https://github.com/stamparm/ipsum
      - Licencia: MIT License (Copyright (c) Stamparm).
      - Uso: Consolidación de direcciones IP maliciosas y reputación de abuso de red.

   f) Spamhaus DROP / EDROP Blocklists:
      - Mantenedor: The Spamhaus Project.
      - Enlace: https://www.spamhaus.org/drop/
      - Licencia: Uso Gratuito Automatizado para Ciberdefensa de SOC / Redes.
      - Uso: Identificación in-memory de rangos de abuso y secuestro de subredes.

   g) Cloud & Datacenter Ranges (AWS, GCP, Azure, Oracle OCI, DigitalOcean, Alibaba Aliyun, Tencent Cloud, Vultr, FireHOL Datacenter):
      - Mantenedores: Amazon Web Services, Google LLC, Microsoft Corporation, Oracle Corporation, DigitalOcean LLC, Alibaba Group, Tencent Holdings, Vultr / Constant Co, FireHOL Project.
      - Licencias: Distribución Oficial Libre / Creative Commons Attribution-ShareAlike 4.0 International (CC-BY-SA 4.0).
      - Uso: Clasificación in-memory de subredes e infraestructura Cloud, Datacenters y VPS a nivel mundial.

   i) MaxMind GeoLite2 ASN Database:
      - Mantenedor: MaxMind, Inc.
      - Enlace: https://www.maxmind.com
      - Licencia: MaxMind GeoLite2 EULA.
      - Uso: Resolución in-memory de Número de Sistema Autónomo (ASN) e ISP.

   j) Google Fonts (Inter, Outfit, JetBrains Mono):
      - Licencia: SIL Open Font License 1.1 / Apache License 2.0.
      - Uso: Presentación gráfica y tipografía en el Dashboard UI de monitoreo.

   k) Frameworks y Librerías Backend (FastAPI, Starlette, Pydantic, Uvicorn, Redis, netaddr, PyJWT, APScheduler, SlowAPI, Structlog, Prometheus Client):
      - Licencia: MIT License / BSD License / Apache License 2.0.
      - Uso: Servidor web asíncrono, motor de matching en memoria, caché PII Zero, validación JWT y telemetría de métricas.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### Fuentes de Datos e Inteligencia de Terceros

Todas las fuentes de datos utilizadas por esta API cumplen estrictamente con sus respectivos términos de servicio y licencias de distribución pública no comercial / defensiva:

1. **MaxMind GeoLite2**: *This product includes GeoLite2 data created by MaxMind, available from [https://www.maxmind.com](https://www.maxmind.com).*
2. **Tor Project Exit List**: Publicado bajo dominio público / BSD por *The Tor Project, Inc.*
3. **Spamhaus DROP / EDROP**: Proporcionado para defensa cibernética automatizada por *The Spamhaus Project*.
4. **FireHOL L1 Blocklist & Datacenter Netset**: Licenciado bajo *Creative Commons Attribution-ShareAlike 4.0 International (CC-BY-SA 4.0) by FireHOL Project*.
5. **Team Cymru Fullbogons**: Proporcionado para ciberdefensa operacional y seguridad por *Team Cymru*.
6. **Cloudflare & Fastly IP Ranges**: Publicados para integración técnica de seguridad de origen por *Cloudflare, Inc.* y *Fastly, Inc.*
7. **AWS, GCP, Azure, Oracle Cloud (OCI), DigitalOcean, Alibaba Cloud (Aliyun), Tencent Cloud & Vultr**: Publicados bajo acceso público libre / distribución de ciberdefensa por sus respectivos proveedores (*Amazon Web Services*, *Google LLC*, *Microsoft Corp*, *Oracle*, *DigitalOcean*, *Alibaba Group*, *Tencent*, *Vultr*).
8. **Abuse.ch Botnet C2 (Feodo Tracker / ThreatFox)**: Publicado bajo *Creative Commons CC0 1.0 Universal (CC0 1.0) Public Domain Dedication* por *abuse.ch*.
9. **OpenPhish Community Feed**: Proporcionado para ciberdefensa y seguridad operacional por *OpenPhish*.
10. **PhishTank & IPsum Feeds**: Proporcionados para investigación y prevención de fraude cibernético con atribución a *PhishTank (Cisco Talos)* y *Stamparm (MIT License)*.
11. **Apple Private Relay**: Publicado oficialmente por *Apple Inc.* para identificación de egress de privacidad.
