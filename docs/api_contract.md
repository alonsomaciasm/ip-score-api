# Contrato de la API de Score de Reputación de IP (API Specification & Contract)

Especificación técnica oficial y contrato formal de la **API de Score de Reputación de IP**. Construida bajo los principios de **PII Zero**, **Security by Design** y **Privacy by Design**.

---

## 📌 Información General

- **Versión de API**: `1.1.0`
- **Protocolo**: HTTPS / JSON (UTF-8)
- **Prefijo Base**: `/api/v1`
- **Formato de Respuestas de Error**: [RFC 7807 (Problem Details for HTTP APIs)](https://tools.ietf.org/html/rfc7807)

---

## 🔒 Autenticación Dual (API Key o Bearer JWT)

La API admite **dos mecanismos de autenticación segura**:

### Cabeceras de Petición (Request Headers)

| Cabecera | Requerido | Tipo | Descripción | Ejemplo |
| :--- | :--- | :--- | :--- | :--- |
| `X-API-Key` | Condicional | String | Clave de API enviada para autenticación por API Key. | `sk_live_prod_key_12345` |
| `Authorization` | Condicional | String | Token JWT de corta duración enviado en formato Bearer Token. | `Bearer eyJhbGciOiJIUzI1Ni...` |
| `X-Request-ID` | Opcional | String | Identificador único de correlación enviado por el cliente para trazabilidad. Si se omite, la API genera un UUIDv4 automáticamente. | `req_9a8b7c6d-5e4f` |
| `Content-Type` | **Sí** (POST) | String | Formato del cuerpo del mensaje. Debe ser `application/json`. | `application/json` |

### Scopes Disponibles

- `score:read`: Permiso para consultar endpoints de scoring individual y por lote.
- `metrics:read`: Permiso para consultar el endpoint de métricas Prometheus.
- `admin:feeds`: Permiso administrativo para forzar la recarga manual de los feeds de inteligencia.

---

## 🚀 Endpoints de la API

### 1. Evaluador Individual de Riesgo (`POST /api/v1/score`)

Evalúa una única dirección IPv4 o IPv6 y retorna el score de riesgo (0-100), banderas de red, nivel de riesgo y recomendación.

#### Request Body
```json
{
  "ip": "185.220.101.5",
  "allow_private": false
}
```

##### Esquema de Petición (Request Schema)
| Campo | Tipo | Requerido | Validaciones / Restricciones |
| :--- | :--- | :--- | :--- |
| `ip` | String | **Sí** | Dirección IPv4 o IPv6 válida. Rechaza rangos privados (RFC 1918), loopback (`127.0.0.1`, `::1`) y direcciones bogon/reservadas con error HTTP 400 (a menos que `allow_private: true` o `ALLOW_PRIVATE_IPS_FOR_TESTING=true`). |
| `allow_private` | Boolean | Opcional | Permite simular y evaluar direcciones IP privadas en modo de pruebas (por defecto `false`). |

#### Response Body (200 OK)
```json
{
  "ip_version": 4,
  "risk_score": 100,
  "risk_level": "critical",
  "recommendation": "block",
  "flags": {
    "is_vpn": false,
    "is_proxy": true,
    "is_tor": true,
    "is_datacenter": false,
    "is_residential": false,
    "is_mobile": false,
    "is_abuse_listed": false,
    "is_icloud_relay": false
  },
  "network": {
    "asn": 62240,
    "asn_org": "Clouvider Ltd",
    "network_type": "hosting"
  },
  "location": {
    "country_code": "DE",
    "country_name": "Germany"
  },
  "confidence": 0.8,
  "signals_used": [
    "tor_exit_list",
    "known_proxy_range"
  ],
  "ttl_seconds": 300
}
```

##### Diccionario de Datos de Respuesta (Response Data Dictionary)

| Campo | Tipo | Valores Posibles / Descripción |
| :--- | :--- | :--- |
| `ip_version` | Integer | `4` o `6`. Versión del protocolo IP evaluado. |
| `risk_score` | Integer | Entero entre `0` (Sin riesgo) y `100` (Riesgo crítico / IP maliciosa). |
| `risk_level` | String (Enum) | `low` (0-29), `medium` (30-59), `high` (60-84), `critical` (85-100). |
| `recommendation` | String (Enum) | `allow` (Permitir), `flag` (Monitorear), `challenge` (CAPTCHA/2FA), `block` (Bloquear). |
| `flags.is_vpn` | Boolean | `true` si la IP pertenece a una red VPN conocida o iCloud Private Relay. |
| `flags.is_proxy` | Boolean | `true` si la IP está clasificada como Open Proxy o nodo Tor. |
| `flags.is_tor` | Boolean | `true` si la IP coincide con un nodo de salida oficial de Tor. |
| `flags.is_datacenter` | Boolean | `true` si la IP pertenece a un proveedor Cloud/Datacenter (AWS, GCP, Azure, Hetzner, DO). |
| `flags.is_residential` | Boolean | `true` si el ASN / ISP corresponde a una red residencial. |
| `flags.is_mobile` | Boolean | `true` si el ASN corresponde a una red celular/móvil. |
| `flags.is_abuse_listed` | Boolean | `true` si la IP figura en listas de abuso activas (Spamhaus DROP / FireHOL L1 / OpenPhish / C2). |
| `flags.is_icloud_relay` | Boolean | `true` si la IP pertenece a los rangos oficiales de Apple Private Relay. |
| `flags.is_botnet_c2` | Boolean | `true` si la IP es un servidor de Comando y Control de Botnet activo (Abuse.ch Feodo Tracker / ThreatFox). |
| `flags.is_bogon` | Boolean | `true` si la IP pertenece a un rango de subred no asignado por IANA (Team Cymru Fullbogons). |
| `flags.is_cdn_egress` | Boolean | `true` si la IP pertenece a los nodos oficiales de egreso de CDN (Cloudflare / Fastly). |
| `flags.is_tor_relay` | Boolean | `true` si la IP coincide con un nodo de retransmisión Guard/Middle de la red Tor. |
| `network.asn` | Integer / null | Número de Sistema Autónomo (ASN) registrado en MaxMind. |
| `network.asn_org` | String | Nombre de la organización o ISP propietario del ASN. |
| `network.network_type` | String | Categoría de red (`education_government`, `hosting`, `residential`, `mobile`, `business`, `trusted`, `blocked`, `unknown`). |
| `location.country_code` | String / null | Código de país ISO 3166-1 alpha-2 (ej. `MX`, `US`, `DE`). |
| `location.country_name` | String | Nombre completo del país según registros MaxMind / Feeds (ej. `Mexico`, `United States`). |
| `confidence` | Float | Índice de confianza del cálculo (`0.0` a `1.0`). |
| `signals_used` | Array[String] | Lista explícita de reglas/señales activadas para justificar el score. |
| `ttl_seconds` | Integer | Tiempo de vida recomendado para caché local en el cliente (segundos). |

##### Catálogo de Señales Posibles en `signals_used`

| Señal | Ponderación | Descripción |
| :--- | :--- | :--- |
| `botnet_c2_server` | `+100 pts` | Servidor de Control de Botnet activo identificado por **Abuse.ch (ThreatFox / Feodo Tracker)**. |
| `active_phishing_host` | `+95 pts` | Servidor albergando sitios de Phishing activos identificados por **OpenPhish y PhishTank (Cisco Talos)**. |
| `bogon_unassigned_range` | `+95 pts` | Rango de subred no asignado por IANA registrado por **Team Cymru Fullbogons** (*Spoofing*). |
| `tor_exit_list` | `+90 pts` | Nodo de salida oficial de la red Tor. |
| `greensnow_threat_list` | `+75 pts` | IP atacante / proxy malicioso identificado en **GreenSnow Threat Feed**. |
| `known_proxy_range` | `+75 pts` | Rango de proxy abierto o anonimizador comercial. |
| `abuse_blocklist_listed` | `+70 pts` | IP listada en Spamhaus DROP / EDROP o FireHOL L1. |
| `vpn_range` | `+50 pts` | Servidor VPN comercial. |
| `tor_relay_node` | `+40 pts` | Nodo Tor Relay (Guard / Middle Node) del consenso oficial de The Tor Project. |
| `datacenter_asn` | `+35 pts` | Proveedor Cloud o Datacenter (AWS, GCP, Azure, Hetzner, DigitalOcean, Aliyun, Tencent, Vultr). |
| `subnet_velocity_anomaly` | `+30 pts` | Pico de rotación de IPs en la subred `/24` o `/48` en menos de 1 hora. |
| `subnet_cluster_hostile` | `+25 pts` | Concentración de múltiples IPs hostiles (C2/Phishing) en la misma subred `/24` o `/48`. |
| `recent_threat_activity` | `+20 pts` | Amenaza detectada e ingesta en las últimas 6 horas (Ponderación por recencia temporal). |
| `icloud_private_relay` | `+15 pts` | Rango oficial de egreso de Apple Private Relay. |
| `cdn_edge_egress` | `+10 pts` | Nodo de egreso de CDN / Edge oficial (Cloudflare / Fastly). |
| `verified_search_engine_bot` | Forzado `0` | Bot de buscador auténtico verificado mediante **FCrDNS (Forward-Confirmed Reverse DNS)**. |
| `trusted_educational_government_network` | Mitigación | Red perteneciente a Universidades, Centros de Investigación o Gobiernos (Confianza `1.0`). |
| `custom_allowlist_override` | Forzado `0` | Forzado de score a `0` (Allow) por lista blanca corporativa local (`data/overrides.json`). |
| `custom_denylist_override` | Forzado `100` | Forzado de score a `100` (Block) por lista negra corporativa local (`data/overrides.json`). |

---

### 2. Evaluador Masivo por Lote (`POST /api/v1/score/batch`)

Evalúa un lote de hasta 50 direcciones IP en una sola petición.

---

### 3. Reporte de Auditoría de Seguridad (`GET /api/v1/health/security`)

Proporciona un informe en tiempo real sobre la integridad criptográfica de los 10 feeds cargados (firmas SHA-256), rotación de salt UTC diaria, estado de PII Zero y uso de memoria RSS.

```json
{
  "status": "secure",
  "version": "1.1.0",
  "pii_zero_active": true,
  "pii_scrubber_enabled": true,
  "salt_rotation": {
    "active_utc_date": "2026-08-16",
    "rotation_interval": "daily"
  },
  "overrides": {
    "allowlist_cidrs": 1,
    "denylist_cidrs": 1
  },
  "feed_checksums_sha256": {
    "tor.txt": "5b3f0da79224d4bd0eccb778b03e584123ca876eed6d9161c7494a16c2a7cd95",
    "bogons.txt": "682baa822e3d02d7a351797a52e2a6650c8058f44f8b8cf4a18f2fec518e5024",
    "botnet_c2.txt": "aecc9256c99eea01ddda464e990591eae339f29b0cdbcf55cab39c43ee655228",
    "phishing.txt": "42f9b8c0e12d34a56b78c9d012e345f67a890b12c3456d789e012f3456a789b0",
    "aws.json": "b86d56680f55f4b386da5480602b1d08fa6bea65a8b4ae342208725d0e51de97",
    "gcp.json": "c780ee9f771e97b8872bd223ca362a2b4d34efcd8dec79485eb92b9b24e51cbf",
    "cloudflare.txt": "d89bc053e3ef30a0b3f8340068b73f8b1e4c0f1047248d29f22f10dfffffb177",
    "fastly.json": "e9ac51975df52d3320851090fa01671c98ac8d4db61822ec6d3ab1b6ce3b0b29",
    "abuse.txt": "86d039315196187bcfeed98d916846f117091ebc46de0a4861aa301d30eaf3d7",
    "apple_relay.csv": "5aa3c2e0af2ceb7336908cecf5441d4dea0998af1e1654a32546d22054ee0ee2"
  },
  "runtime": {
    "uptime_seconds": 18.76,
    "rss_memory_mb": 211.03
  }
}
```

---

### 4. Endpoint de Métricas Prometheus (`GET /api/v1/metrics`)

Retorna métricas agregadas de rendimiento y negocio en formato estándar de Prometheus (Requiere scope `metrics:read`).

---

### 5. Recarga Manual de Feeds (`POST /api/v1/admin/feeds/refresh`)

Fuerza la descarga asíncrona e in-memory reload inmediata de las 10 fuentes de inteligencia (Requiere scope `admin:feeds`).
