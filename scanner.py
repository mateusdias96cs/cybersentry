import requests
import socket
import ssl
import datetime
import dns.resolver
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# ── VALIDAÇÃO DE URL ──
def validar_url(url):
    try:
        resultado = urlparse(url)
        if resultado.scheme not in ("http", "https"):
            return False, "URL deve começar com http:// ou https://"
        if not resultado.netloc:
            return False, "URL inválida — domínio não encontrado"
        return True, ""
    except Exception:
        return False, "URL malformada"

def extrair_hostname(url):
    return urlparse(url).netloc.split(":")[0]

# ── INPUT SEGURO ──
url = input("\n🔍 Digite a URL para escanear (ex: https://www.google.com): ").strip()

valida, motivo = validar_url(url)
if not valida:
    print(f"\n[ERRO] {motivo}")
    exit(1)

hostname = extrair_hostname(url)

if not hostname:
    print("\n[ERRO] Não foi possível extrair o domínio da URL.")
    exit(1)

# ── MÓDULOS ──

def checar_headers(url):
    print(f"\nAnalisando headers: {url}\n")
    headers_seguranca = [
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Content-Security-Policy",
        "Strict-Transport-Security",
    ]
    try:
        resposta = requests.get(url, timeout=10, allow_redirects=True)
        for header in headers_seguranca:
            if header in resposta.headers:
                print(f"[✓] {header} — presente")
            else:
                print(f"[✗] {header} — AUSENTE")
    except requests.exceptions.ConnectionError:
        print("[!] Não foi possível conectar ao site")
    except requests.exceptions.Timeout:
        print("[!] Timeout — site demorou demais para responder")
    except Exception as e:
        print(f"[!] Erro inesperado ao checar headers — {type(e).__name__}")

def checar_cookies(url):
    print(f"\nCookies de: {url}\n")
    try:
        resposta = requests.get(url, timeout=10, allow_redirects=True)
        if not resposta.cookies:
            print("[i] Nenhum cookie encontrado.")
            return
        for cookie in resposta.cookies:
            print(f"Cookie: {cookie.name}")
            print(f"  Secure: {cookie.secure}")
            print(f"  HttpOnly: {'HttpOnly' in str(cookie)}")
            print()
    except requests.exceptions.ConnectionError:
        print("[!] Não foi possível conectar ao site")
    except requests.exceptions.Timeout:
        print("[!] Timeout ao checar cookies")
    except Exception as e:
        print(f"[!] Erro inesperado ao checar cookies — {type(e).__name__}")

def checar_https(url):
    print(f"\nChecando HTTPS: {url}\n")
    try:
        if url.startswith("https://"):
            print("[✓] Site usa HTTPS")
        else:
            print("[✗] Site NÃO usa HTTPS — tráfego exposto")

        url_http = url.replace("https://", "http://").replace("http://", "http://", 1)
        if not url_http.startswith("http://"):
            url_http = "http://" + url_http

        resposta = requests.get(url_http, allow_redirects=False, timeout=5)
        if resposta.status_code in [301, 302]:
            print("[✓] Redireciona HTTP para HTTPS")
        else:
            print("[✗] NÃO redireciona HTTP para HTTPS — vulnerável")
    except requests.exceptions.ConnectionError:
        print("[!] Não foi possível testar redirecionamento HTTP")
    except requests.exceptions.Timeout:
        print("[!] Timeout ao testar redirecionamento")
    except Exception as e:
        print(f"[!] Erro inesperado ao checar HTTPS — {type(e).__name__}")

def checar_portas(host):
    print(f"\nChecando portas: {host}\n")
    portas_comuns = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL",
        8080: "HTTP alternativo",
    }
    for porta, servico in portas_comuns.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            resultado = sock.connect_ex((host, porta))
            if resultado == 0:
                print(f"[!] Porta {porta} ({servico}) — ABERTA")
            else:
                print(f"[ ] Porta {porta} ({servico}) — fechada")
        except socket.gaierror:
            print(f"[!] Não foi possível resolver o host: {host}")
            break
        except Exception as e:
            print(f"[!] Erro ao checar porta {porta} — {type(e).__name__}")
        finally:
            sock.close()

def checar_cors(url):
    print(f"\nChecando CORS: {url}\n")
    try:
        headers_teste = {"Origin": "https://site-malicioso.com"}
        resposta = requests.get(url, headers=headers_teste, timeout=10)
        acao = resposta.headers.get("Access-Control-Allow-Origin", None)
        credenciais = resposta.headers.get("Access-Control-Allow-Credentials", None)

        if acao is None:
            print("[✓] CORS não configurado — sem risco de exposição")
        elif acao == "*":
            print("[!] CORS aberto para qualquer origem — ATENÇÃO")
        elif acao == "https://site-malicioso.com":
            print("[✗] Servidor reflete origem maliciosa — VULNERÁVEL")
        else:
            print(f"[✓] CORS restrito para: {acao}")

        if credenciais and credenciais.lower() == "true":
            print("[✗] Permite credenciais cross-origin — CRÍTICO")
        else:
            print("[✓] Não permite credenciais cross-origin")
    except requests.exceptions.ConnectionError:
        print("[!] Não foi possível conectar ao site")
    except requests.exceptions.Timeout:
        print("[!] Timeout ao checar CORS")
    except Exception as e:
        print(f"[!] Erro inesperado ao checar CORS — {type(e).__name__}")

def checar_ssl(hostname):
    print(f"\nChecando SSL/TLS: {hostname}\n")
    try:
        contexto = ssl.create_default_context()
        with contexto.wrap_socket(
            socket.socket(),
            server_hostname=hostname
        ) as sock:
            sock.settimeout(5)
            sock.connect((hostname, 443))
            certificado = sock.getpeercert()
            versao = sock.version()

            validade_str = certificado['notAfter']
            validade = datetime.datetime.strptime(validade_str, "%b %d %H:%M:%S %Y %Z")
            hoje = datetime.datetime.utcnow()
            dias_restantes = (validade - hoje).days

            if dias_restantes < 0:
                print(f"[✗] Certificado VENCIDO há {abs(dias_restantes)} dias — CRÍTICO")
            elif dias_restantes < 30:
                print(f"[!] Certificado vence em {dias_restantes} dias — ATENÇÃO")
            else:
                print(f"[✓] Certificado válido por mais {dias_restantes} dias")

            print(f"[i] Protocolo: {versao}")

            emissor = dict(x[0] for x in certificado['issuer'])
            print(f"[i] Emissor: {emissor.get('organizationName', 'desconhecido')}")

    except ssl.CertificateError as e:
        print(f"[✗] Certificado inválido — {e}")
    except ssl.SSLError as e:
        print(f"[✗] Erro SSL — {e}")
    except socket.timeout:
        print("[!] Timeout ao conectar para checar SSL")
    except socket.gaierror:
        print(f"[!] Não foi possível resolver o host: {hostname}")
    except Exception as e:
        print(f"[!] Erro inesperado ao checar SSL — {type(e).__name__}")

def checar_dns_email(hostname):
    print(f"\nChecando DNS/Email: {hostname}\n")

    # SPF
    try:
        respostas = dns.resolver.resolve(hostname, 'TXT')
        spf_encontrado = False
        for r in respostas:
            if 'v=spf1' in str(r):
                spf_encontrado = True
                print(f"[✓] SPF configurado — {str(r)[:60]}")
        if not spf_encontrado:
            print("[✗] SPF não encontrado — domínio pode ser usado em phishing")
    except dns.resolver.NXDOMAIN:
        print("[!] Domínio não encontrado no DNS")
    except dns.resolver.NoAnswer:
        print("[✗] SPF não encontrado — sem registros TXT")
    except Exception:
        print("[!] Não foi possível checar SPF")

    # DMARC
    try:
        respostas = dns.resolver.resolve(f"_dmarc.{hostname}", 'TXT')
        for r in respostas:
            if 'v=DMARC1' in str(r):
                print(f"[✓] DMARC configurado — {str(r)[:60]}")
    except dns.resolver.NXDOMAIN:
        print("[✗] DMARC não encontrado — emails falsificados não são bloqueados")
    except dns.resolver.NoAnswer:
        print("[✗] DMARC não encontrado — sem registros TXT")
    except Exception:
        print("[!] Não foi possível checar DMARC")

    # DKIM
    try:
        respostas = dns.resolver.resolve(f"default._domainkey.{hostname}", 'TXT')
        for r in respostas:
            print(f"[✓] DKIM encontrado")
    except Exception:
        print("[!] DKIM não encontrado no seletor padrão")

def checar_sql_injection(url):
    print(f"\nChecando SQL Injection: {url}\n")

    payloads = ["'", '"', "' OR '1'='1", "' OR 1=1--", '"OR""="']
    erros_sql = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "pg_query",
        "sqlite3",
    ]

    try:
        resposta = requests.get(url, timeout=10)
        soup = BeautifulSoup(resposta.text, 'html.parser')
        forms = soup.find_all('form')

        if not forms:
            print("[i] Nenhum formulário encontrado na página")
            return

        print(f"[i] {len(forms)} formulário(s) encontrado(s)")

        for i, form in enumerate(forms):
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            form_url = urljoin(url, action)

            inputs = form.find_all('input')
            dados = {}
            for inp in inputs:
                nome = inp.get('name', f'campo_{i}')
                dados[nome] = 'teste'

            for payload in payloads:
                dados_teste = {k: payload for k in dados}
                try:
                    if method == 'post':
                        r = requests.post(form_url, data=dados_teste, timeout=5)
                    else:
                        r = requests.get(form_url, params=dados_teste, timeout=5)

                    for erro in erros_sql:
                        if erro in r.text.lower():
                            print(f"[✗] SQL Injection detectado — payload: {payload}")
                            return
                except requests.exceptions.Timeout:
                    continue
                except Exception:
                    continue

        print("[✓] Nenhuma vulnerabilidade SQL detectada nos formulários")

    except requests.exceptions.ConnectionError:
        print("[!] Não foi possível conectar ao site")
    except requests.exceptions.Timeout:
        print("[!] Timeout ao checar SQL Injection")
    except Exception as e:
        print(f"[!] Erro inesperado ao checar SQL Injection — {type(e).__name__}")

def checar_xss(url):
    print(f"\nChecando XSS: {url}\n")

    payloads = [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert('xss')>",
        "'><script>alert('xss')</script>",
    ]

    try:
        resposta = requests.get(url, timeout=10)
        soup = BeautifulSoup(resposta.text, 'html.parser')
        forms = soup.find_all('form')

        if not forms:
            print("[i] Nenhum formulário encontrado na página")
            return

        print(f"[i] {len(forms)} formulário(s) encontrado(s)")

        for i, form in enumerate(forms):
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            form_url = urljoin(url, action)

            inputs = form.find_all('input')
            dados = {}
            for inp in inputs:
                nome = inp.get('name', f'campo_{i}')
                dados[nome] = 'teste'

            for payload in payloads:
                dados_teste = {k: payload for k in dados}
                try:
                    if method == 'post':
                        r = requests.post(form_url, data=dados_teste, timeout=5)
                    else:
                        r = requests.get(form_url, params=dados_teste, timeout=5)

                    if payload in r.text:
                        print(f"[✗] XSS detectado — payload refletido: {payload[:40]}")
                        return
                except requests.exceptions.Timeout:
                    continue
                except Exception:
                    continue

        print("[✓] Nenhuma vulnerabilidade XSS detectada nos formulários")

    except requests.exceptions.ConnectionError:
        print("[!] Não foi possível conectar ao site")
    except requests.exceptions.Timeout:
        print("[!] Timeout ao checar XSS")
    except Exception as e:
        print(f"[!] Erro inesperado ao checar XSS — {type(e).__name__}")

# ── EXECUÇÃO ──
print(f"\n{'='*50}")
print(f"  CYBERSENTRY — Scan de {hostname}")
print(f"{'='*50}")

checar_headers(url)
checar_cookies(url)
checar_https(url)
checar_portas(hostname)
checar_cors(url)
checar_ssl(hostname)
checar_dns_email(hostname)
checar_sql_injection(url)
checar_xss(url)

print(f"\n{'='*50}")
print(f"  Scan concluído.")
print(f"{'='*50}\n")
