# CyberSentry API — Documentação para Frontend

## Visão Geral

A API do CyberSentry recebe uma URL, executa um scan de vulnerabilidades e retorna os resultados em JSON. Também mantém histórico de todos os scans realizados.

**Base URL (local):** `http://127.0.0.1:8000`

**Documentação interativa:** `http://127.0.0.1:8000/docs`

---

## Endpoints

### GET /
Verifica se a API está online.

**Resposta:**
```json
{
  "status": "online",
  "produto": "CyberSentry"
}
```

---

### POST /scan
Realiza um scan completo de vulnerabilidades em uma URL.

**Request:**
```json
{
  "url": "https://exemplo.com.br"
}
```

**Resposta (200):**
```json
{
  "id": 1,
  "url": "https://exemplo.com.br",
  "hostname": "exemplo.com.br",
  "criado_em": "2026-04-10T19:55:08.631462",
  "resultados": {
    "headers": {
      "X-Frame-Options": true,
      "X-Content-Type-Options": false,
      "Content-Security-Policy": false,
      "Strict-Transport-Security": false
    },
    "cookies": [
      {
        "nome": "session",
        "secure": true,
        "httponly": false
      }
    ],
    "https": {
      "usa_https": true,
      "redireciona_https": true
    },
    "portas": {
      "21": { "servico": "FTP", "aberta": false },
      "22": { "servico": "SSH", "aberta": false },
      "23": { "servico": "Telnet", "aberta": false },
      "80": { "servico": "HTTP", "aberta": true },
      "443": { "servico": "HTTPS", "aberta": true },
      "3306": { "servico": "MySQL", "aberta": false },
      "8080": { "servico": "HTTP alternativo", "aberta": false }
    },
    "cors": {
      "allow_origin": null,
      "allow_credentials": null
    },
    "ssl": {
      "dias_restantes": 62,
      "protocolo": "TLSv1.3",
      "emissor": "Google Trust Services"
    },
    "dns_email": {
      "spf": "\"v=spf1 include:_spf.mail.hostinger.com ~all\"",
      "dmarc": "\"v=DMARC1; p=none;\"",
      "dkim": false
    },
    "sql_injection": {
      "vulneravel": false,
      "payload": null
    },
    "xss": {
      "vulneravel": false,
      "payload": null
    }
  }
}
```

**Resposta (400) — URL inválida:**
```json
{
  "detail": "URL deve começar com http:// ou https://"
}
```

---

### GET /historico
Retorna lista de todos os scans realizados, do mais recente para o mais antigo.

**Resposta:**
```json
[
  {
    "id": 2,
    "url": "https://outro-site.com",
    "hostname": "outro-site.com",
    "criado_em": "2026-04-10T20:10:00.000000"
  },
  {
    "id": 1,
    "url": "https://exemplo.com.br",
    "hostname": "exemplo.com.br",
    "criado_em": "2026-04-10T19:55:08.631462"
  }
]
```

---

### GET /historico/{id}
Retorna o scan completo de um ID específico.

**Exemplo:** `GET /historico/1`

**Resposta (200):** mesmo formato do POST /scan

**Resposta (404):**
```json
{
  "detail": "Scan não encontrado"
}
```

---

## Como integrar no frontend

### Exemplo com fetch (JavaScript)

```javascript
// Realizar um scan
const response = await fetch('http://127.0.0.1:8000/scan', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ url: 'https://exemplo.com.br' })
});
const data = await response.json();
console.log(data.resultados);

// Buscar histórico
const historico = await fetch('http://127.0.0.1:8000/historico');
const lista = await historico.json();

// Buscar scan por ID
const scan = await fetch('http://127.0.0.1:8000/historico/1');
const detalhes = await scan.json();
```

---

## Estrutura dos Resultados

| Campo | Tipo | Descrição |
|---|---|---|
| `headers` | object | Presença de headers de segurança (true/false) |
| `cookies` | array | Lista de cookies com flags Secure e HttpOnly |
| `https.usa_https` | boolean | Site usa HTTPS |
| `https.redireciona_https` | boolean | HTTP redireciona para HTTPS |
| `portas` | object | Portas abertas por número |
| `cors.allow_origin` | string/null | Política de CORS configurada |
| `ssl.dias_restantes` | integer | Dias até expirar o certificado |
| `ssl.protocolo` | string | Versão do protocolo TLS |
| `dns_email.spf` | string/null | Registro SPF do domínio |
| `dns_email.dmarc` | string/null | Registro DMARC do domínio |
| `dns_email.dkim` | boolean | DKIM encontrado |
| `sql_injection.vulneravel` | boolean | Vulnerabilidade detectada |
| `xss.vulneravel` | boolean | Vulnerabilidade detectada |

---

## Como rodar a API localmente

```bash
# Instalar dependências
pip install fastapi uvicorn sqlalchemy requests dnspython beautifulsoup4

# Rodar o servidor
uvicorn main:app --reload
```

A API estará disponível em `http://127.0.0.1:8000`.

---

## Observações

- O scan pode demorar entre **15 e 60 segundos** dependendo do site
- Recomenda-se mostrar um loading enquanto aguarda a resposta
- O campo `criado_em` está em UTC — ajustar para horário de Brasília (UTC-3) no frontend
