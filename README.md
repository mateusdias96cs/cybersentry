# 🛡️ CyberSentry

> Web vulnerability scanner for small and medium businesses.

CyberSentry é um scanner de vulnerabilidades web desenvolvido em Python, focado em ajudar pequenas e médias empresas a identificar falhas de segurança básicas em seus sistemas — sem precisar de uma equipe de segurança dedicada.

---

## 🔍 O que o CyberSentry detecta

| Módulo | O que verifica |
|---|---|
| Headers de segurança | X-Frame-Options, CSP, HSTS, X-Content-Type-Options |
| Cookies | Flag Secure e HttpOnly |
| HTTPS | Uso de HTTPS e redirecionamento HTTP → HTTPS |
| Portas abertas | FTP, SSH, Telnet, MySQL, HTTP alternativo |
| CORS | Configuração incorreta de Cross-Origin Resource Sharing |
| SSL/TLS | Validade do certificado, protocolo e emissor |
| DNS/Email | SPF, DMARC e DKIM configurados corretamente |
| SQL Injection | Detecção de formulários vulneráveis a injeção SQL |
| XSS | Detecção de formulários vulneráveis a Cross-Site Scripting |

---

## 🚀 Como usar

**Requisitos**
- Python 3.10+
- pip

**Instalação**

```bash
git clone https://github.com/mateusdias96cs/cybersentry.git
cd cybersentry
pip install -r requirements.txt
```

**Execução**

```bash
python scanner.py
```

Digite a URL quando solicitado:

```
🔍 Digite a URL para escanear (ex: https://www.google.com): https://seusite.com.br
```

---

## 📋 Exemplo de resultado

```
==================================================
  CYBERSENTRY — Scan de seusite.com.br
==================================================

Analisando headers: https://seusite.com.br
[✓] X-Frame-Options — presente
[✗] X-Content-Type-Options — AUSENTE
[✗] Content-Security-Policy — AUSENTE

Checando SSL/TLS: seusite.com.br
[✓] Certificado válido por mais 64 dias
[i] Protocolo: TLSv1.3

Checando DNS/Email: seusite.com.br
[✓] SPF configurado
[✗] DMARC não encontrado — emails falsificados não são bloqueados
==================================================
  Scan concluído.
==================================================
```

---

## 🛠️ Tecnologias

- Python 3.10
- requests
- dnspython
- beautifulsoup4
- ssl (nativo)
- socket (nativo)

---

## ⚠️ Aviso Legal

Este scanner deve ser usado **apenas em domínios que você possui ou tem autorização explícita para testar**. O uso não autorizado pode ser ilegal. O desenvolvedor não se responsabiliza pelo uso indevido desta ferramenta.

---

## 👨‍💻 Autor

**Mateus Camara Dias**  
Desenvolvido como parte do projeto CyberSentry — Empreenda SENAC 2026.
