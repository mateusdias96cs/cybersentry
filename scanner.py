import requests
import socket
import ssl
import datetime
import dns.resolver
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


class CyberSentry:
    """Scanner de vulnerabilidades web para pequenas e médias empresas."""

    def __init__(self, url: str):
        self.url = url
        self.hostname = self._extrair_hostname(url)
        self.resultados = {}

    # ── UTILITÁRIOS ──

    @staticmethod
    def validar_url(url: str) -> tuple[bool, str]:
        try:
            resultado = urlparse(url)
            if resultado.scheme not in ("http", "https"):
                return False, "URL deve começar com http:// ou https://"
            if not resultado.netloc:
                return False, "URL inválida — domínio não encontrado"
            return True, ""
        except Exception:
            return False, "URL malformada"

    @staticmethod
    def _extrair_hostname(url: str) -> str:
        return urlparse(url).netloc.split(":")[0]

    # ── MÓDULOS ──

    def checar_headers(self):
        print(f"\nAnalisando headers: {self.url}\n")
        headers_seguranca = [
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Content-Security-Policy",
            "Strict-Transport-Security",
        ]
        resultado = {}
        try:
            resposta = requests.get(self.url, timeout=10, allow_redirects=True)
            for header in headers_seguranca:
                presente = header in resposta.headers
                resultado[header] = presente
                print(f"[{'✓' if presente else '✗'}] {header} — {'presente' if presente else 'AUSENTE'}")
        except requests.exceptions.ConnectionError:
            print("[!] Não foi possível conectar ao site")
        except requests.exceptions.Timeout:
            print("[!] Timeout — site demorou demais para responder")
        except Exception as e:
            print(f"[!] Erro inesperado ao checar headers — {type(e).__name__}")
        self.resultados['headers'] = resultado

    def checar_cookies(self):
        print(f"\nCookies de: {self.url}\n")
        resultado = []
        try:
            resposta = requests.get(self.url, timeout=10, allow_redirects=True)
            if not resposta.cookies:
                print("[i] Nenhum cookie encontrado.")
            else:
                for cookie in resposta.cookies:
                    info = {
                        "nome": cookie.name,
                        "secure": cookie.secure,
                        "httponly": 'HttpOnly' in str(cookie)
                    }
                    resultado.append(info)
                    print(f"Cookie: {cookie.name}")
                    print(f"  Secure: {cookie.secure}")
                    print(f"  HttpOnly: {info['httponly']}")
                    print()
        except requests.exceptions.ConnectionError:
            print("[!] Não foi possível conectar ao site")
        except requests.exceptions.Timeout:
            print("[!] Timeout ao checar cookies")
        except Exception as e:
            print(f"[!] Erro inesperado ao checar cookies — {type(e).__name__}")
        self.resultados['cookies'] = resultado

    def checar_https(self):
        print(f"\nChecando HTTPS: {self.url}\n")
        resultado = {}
        try:
            usa_https = self.url.startswith("https://")
            resultado['usa_https'] = usa_https
            print(f"[{'✓' if usa_https else '✗'}] Site {'usa' if usa_https else 'NÃO usa'} HTTPS{'.' if usa_https else ' — tráfego exposto'}")

            url_http = "http://" + self.hostname
            resposta = requests.get(url_http, allow_redirects=False, timeout=5)
            redireciona = resposta.status_code in [301, 302]
            resultado['redireciona_https'] = redireciona
            print(f"[{'✓' if redireciona else '✗'}] {'Redireciona' if redireciona else 'NÃO redireciona'} HTTP para HTTPS{'' if redireciona else ' — vulnerável'}")
        except requests.exceptions.ConnectionError:
            print("[!] Não foi possível testar redirecionamento HTTP")
        except requests.exceptions.Timeout:
            print("[!] Timeout ao testar redirecionamento")
        except Exception as e:
            print(f"[!] Erro inesperado ao checar HTTPS — {type(e).__name__}")
        self.resultados['https'] = resultado

    def checar_portas(self):
        print(f"\nChecando portas: {self.hostname}\n")
        portas_comuns = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL",
            8080: "HTTP alternativo",
        }
        resultado = {}
        for porta, servico in portas_comuns.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                aberta = sock.connect_ex((self.hostname, porta)) == 0
                resultado[porta] = {"servico": servico, "aberta": aberta}
                print(f"[{'!' if aberta else ' '}] Porta {porta} ({servico}) — {'ABERTA' if aberta else 'fechada'}")
            except socket.gaierror:
                print(f"[!] Não foi possível resolver o host: {self.hostname}")
                break
            except Exception as e:
                print(f"[!] Erro ao checar porta {porta} — {type(e).__name__}")
            finally:
                sock.close()
        self.resultados['portas'] = resultado

    def checar_cors(self):
        print(f"\nChecando CORS: {self.url}\n")
        resultado = {}
        try:
            headers_teste = {"Origin": "https://site-malicioso.com"}
            resposta = requests.get(self.url, headers=headers_teste, timeout=10)
            acao = resposta.headers.get("Access-Control-Allow-Origin", None)
            credenciais = resposta.headers.get("Access-Control-Allow-Credentials", None)

            resultado['allow_origin'] = acao
            resultado['allow_credentials'] = credenciais

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
        self.resultados['cors'] = resultado

    def checar_ssl(self):
        print(f"\nChecando SSL/TLS: {self.hostname}\n")
        resultado = {}
        try:
            contexto = ssl.create_default_context()
            with contexto.wrap_socket(
                socket.socket(),
                server_hostname=self.hostname
            ) as sock:
                sock.settimeout(5)
                sock.connect((self.hostname, 443))
                certificado = sock.getpeercert()
                versao = sock.version()

                validade_str = certificado['notAfter']
                validade = datetime.datetime.strptime(validade_str, "%b %d %H:%M:%S %Y %Z")
                hoje = datetime.datetime.utcnow()
                dias_restantes = (validade - hoje).days
                emissor = dict(x[0] for x in certificado['issuer'])

                resultado['dias_restantes'] = dias_restantes
                resultado['protocolo'] = versao
                resultado['emissor'] = emissor.get('organizationName', 'desconhecido')

                if dias_restantes < 0:
                    print(f"[✗] Certificado VENCIDO há {abs(dias_restantes)} dias — CRÍTICO")
                elif dias_restantes < 30:
                    print(f"[!] Certificado vence em {dias_restantes} dias — ATENÇÃO")
                else:
                    print(f"[✓] Certificado válido por mais {dias_restantes} dias")

                print(f"[i] Protocolo: {versao}")
                print(f"[i] Emissor: {resultado['emissor']}")

        except ssl.CertificateError as e:
            print(f"[✗] Certificado inválido — {e}")
        except ssl.SSLError as e:
            print(f"[✗] Erro SSL — {e}")
        except socket.timeout:
            print("[!] Timeout ao conectar para checar SSL")
        except socket.gaierror:
            print(f"[!] Não foi possível resolver o host: {self.hostname}")
        except Exception as e:
            print(f"[!] Erro inesperado ao checar SSL — {type(e).__name__}")
        self.resultados['ssl'] = resultado

    def checar_dns_email(self):
        print(f"\nChecando DNS/Email: {self.hostname}\n")
        resultado = {}

        # SPF
        try:
            respostas = dns.resolver.resolve(self.hostname, 'TXT')
            spf_encontrado = False
            for r in respostas:
                if 'v=spf1' in str(r):
                    spf_encontrado = True
                    resultado['spf'] = str(r)[:60]
                    print(f"[✓] SPF configurado — {resultado['spf']}")
            if not spf_encontrado:
                resultado['spf'] = None
                print("[✗] SPF não encontrado — domínio pode ser usado em phishing")
        except dns.resolver.NXDOMAIN:
            print("[!] Domínio não encontrado no DNS")
        except dns.resolver.NoAnswer:
            resultado['spf'] = None
            print("[✗] SPF não encontrado — sem registros TXT")
        except Exception:
            print("[!] Não foi possível checar SPF")

        # DMARC
        try:
            respostas = dns.resolver.resolve(f"_dmarc.{self.hostname}", 'TXT')
            for r in respostas:
                if 'v=DMARC1' in str(r):
                    resultado['dmarc'] = str(r)[:60]
                    print(f"[✓] DMARC configurado — {resultado['dmarc']}")
        except dns.resolver.NXDOMAIN:
            resultado['dmarc'] = None
            print("[✗] DMARC não encontrado — emails falsificados não são bloqueados")
        except dns.resolver.NoAnswer:
            resultado['dmarc'] = None
            print("[✗] DMARC não encontrado — sem registros TXT")
        except Exception:
            print("[!] Não foi possível checar DMARC")

        # DKIM
        try:
            respostas = dns.resolver.resolve(f"default._domainkey.{self.hostname}", 'TXT')
            for r in respostas:
                resultado['dkim'] = True
                print("[✓] DKIM encontrado")
        except Exception:
            resultado['dkim'] = False
            print("[!] DKIM não encontrado no seletor padrão")

        self.resultados['dns_email'] = resultado

    def checar_sql_injection(self):
        print(f"\nChecando SQL Injection: {self.url}\n")
        payloads = ["'", '"', "' OR '1'='1", "' OR 1=1--", '"OR""="']
        erros_sql = [
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark",
            "quoted string not properly terminated",
            "pg_query",
            "sqlite3",
        ]
        resultado = {"vulneravel": False, "payload": None}
        try:
            resposta = requests.get(self.url, timeout=10)
            soup = BeautifulSoup(resposta.text, 'html.parser')
            forms = soup.find_all('form')

            if not forms:
                print("[i] Nenhum formulário encontrado na página")
                self.resultados['sql_injection'] = resultado
                return

            print(f"[i] {len(forms)} formulário(s) encontrado(s)")

            for i, form in enumerate(forms):
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                form_url = urljoin(self.url, action)
                inputs = form.find_all('input')
                dados = {inp.get('name', f'campo_{i}'): 'teste' for inp in inputs}

                for payload in payloads:
                    dados_teste = {k: payload for k in dados}
                    try:
                        if method == 'post':
                            r = requests.post(form_url, data=dados_teste, timeout=5)
                        else:
                            r = requests.get(form_url, params=dados_teste, timeout=5)

                        for erro in erros_sql:
                            if erro in r.text.lower():
                                resultado = {"vulneravel": True, "payload": payload}
                                print(f"[✗] SQL Injection detectado — payload: {payload}")
                                self.resultados['sql_injection'] = resultado
                                return
                    except Exception:
                        continue

            print("[✓] Nenhuma vulnerabilidade SQL detectada nos formulários")
        except requests.exceptions.ConnectionError:
            print("[!] Não foi possível conectar ao site")
        except requests.exceptions.Timeout:
            print("[!] Timeout ao checar SQL Injection")
        except Exception as e:
            print(f"[!] Erro inesperado ao checar SQL Injection — {type(e).__name__}")
        self.resultados['sql_injection'] = resultado

    def checar_xss(self):
        print(f"\nChecando XSS: {self.url}\n")
        payloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "'><script>alert('xss')</script>",
        ]
        resultado = {"vulneravel": False, "payload": None}
        try:
            resposta = requests.get(self.url, timeout=10)
            soup = BeautifulSoup(resposta.text, 'html.parser')
            forms = soup.find_all('form')

            if not forms:
                print("[i] Nenhum formulário encontrado na página")
                self.resultados['xss'] = resultado
                return

            print(f"[i] {len(forms)} formulário(s) encontrado(s)")

            for i, form in enumerate(forms):
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                form_url = urljoin(self.url, action)
                inputs = form.find_all('input')
                dados = {inp.get('name', f'campo_{i}'): 'teste' for inp in inputs}

                for payload in payloads:
                    dados_teste = {k: payload for k in dados}
                    try:
                        if method == 'post':
                            r = requests.post(form_url, data=dados_teste, timeout=5)
                        else:
                            r = requests.get(form_url, params=dados_teste, timeout=5)

                        if payload in r.text:
                            resultado = {"vulneravel": True, "payload": payload}
                            print(f"[✗] XSS detectado — payload refletido: {payload[:40]}")
                            self.resultados['xss'] = resultado
                            return
                    except Exception:
                        continue

            print("[✓] Nenhuma vulnerabilidade XSS detectada nos formulários")
        except requests.exceptions.ConnectionError:
            print("[!] Não foi possível conectar ao site")
        except requests.exceptions.Timeout:
            print("[!] Timeout ao checar XSS")
        except Exception as e:
            print(f"[!] Erro inesperado ao checar XSS — {type(e).__name__}")
        self.resultados['xss'] = resultado

    # ── SCAN COMPLETO ──

    def scan(self):
        print(f"\n{'='*50}")
        print(f"  CYBERSENTRY — Scan de {self.hostname}")
        print(f"{'='*50}")

        self.checar_headers()
        self.checar_cookies()
        self.checar_https()
        self.checar_portas()
        self.checar_cors()
        self.checar_ssl()
        self.checar_dns_email()
        self.checar_sql_injection()
        self.checar_xss()

        print(f"\n{'='*50}")
        print(f"  Scan concluído.")
        print(f"{'='*50}\n")

        return self.resultados


# ── EXECUÇÃO ──
if __name__ == "__main__":
    url = input("\n🔍 Digite a URL para escanear (ex: https://www.google.com): ").strip()

    valida, motivo = CyberSentry.validar_url(url)
    if not valida:
        print(f"\n[ERRO] {motivo}")
        exit(1)

    scanner = CyberSentry(url)
    resultados = scanner.scan()
