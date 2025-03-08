import requests
import socket
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog, filedialog
import platform
import os
import subprocess
import ipaddress
import netifaces
import ssl
import datetime
import time
import concurrent.futures
import json
import sys

try:
    from fpdf import FPDF
except ImportError:
    FPDF = None

try:
    from Wappalyzer import Wappalyzer, WebPage
    WAPPALYZER_AVAILABLE = True
except ImportError:
    WAPPALYZER_AVAILABLE = False

# Variáveis globais e funções de utilidade
is_dark_mode = False
status_var = None
history_file = "scan_history.txt"

def update_status(message):
    status_var.set(message)
    root.update_idletasks()

def save_to_history(entry):
    timestamp = datetime.datetime.now().isoformat()
    log_entry = f"{timestamp}: {entry}\n\n"
    with open(history_file, "a", encoding="utf-8") as f:
        f.write(log_entry)
    # Opcional: salvar também em JSON
    json_file = "scan_history.json"
    data = { "timestamp": timestamp, "entry": entry }
    try:
        if os.path.exists(json_file):
            with open(json_file, "r", encoding="utf-8") as jf:
                logs = json.load(jf)
        else:
            logs = []
    except Exception:
        logs = []
    logs.append(data)
    with open(json_file, "w", encoding="utf-8") as jf:
        json.dump(logs, jf, indent=4)

def load_history():
    if os.path.exists(history_file):
        with open(history_file, "r", encoding="utf-8") as f:
            return f.read()
    return "Sem histórico."

def clear_history():
    with open(history_file, "w", encoding="utf-8") as f:
        f.write("")
    history_text.delete(1.0, tk.END)
    history_text.insert(tk.END, "Histórico limpo.")

# ───────────────────────────────────────────────────────────────
# FUNÇÕES DE ESCANEAMENTO E TESTES

# Função para escanear uma única porta (executada em paralelo)
def scan_port_single(host, port, mode):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        start_time = time.time()
        result = sock.connect_ex((host, port))
        duration = time.time() - start_time
        banner = ""
        if result == 0:
            if mode == "Detalhado":
                try:
                    sock.send(b"\n")
                    banner = sock.recv(1024).decode(errors="ignore").strip()
                    if banner:
                        banner = f" - Banner: {banner}"
                except Exception:
                    banner = ""
            firewall_note = " (Possível firewall)" if duration > 1.5 else ""
            retorno = f"⚠ Porta {port} aberta!{banner}{firewall_note}\n"
            tag = "warn"
        else:
            retorno = f"✔ Porta {port} fechada.\n"
            tag = "ok"
        sock.close()
        return (port, retorno, tag)
    except socket.timeout:
        return (port, f"⚠ Porta {port} timeout.\n", "error")
    except Exception as e:
        return (port, f"Erro na porta {port}: {e}\n", "error")

# 1. Headers & Port Scan (com portas customizadas e modos paralelos)
def check_headers_and_scan_ports(url):
    update_status("Verificando cabeçalhos e escaneando portas...")
    try:
        if not (url.startswith("https://") or url.startswith("http://")):
            url = "https://" + url
        response = requests.get(url, timeout=5)
        headers = response.headers
        security_headers = [
            "Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options",
            "X-XSS-Protection", "X-Content-Type-Options", "Referrer-Policy"
        ]
        
        headers_text.delete(1.0, tk.END)
        headers_text.insert(tk.END, "[+] Verificando cabeçalhos de segurança:\n")
        for header in security_headers:
            if header in headers:
                headers_text.insert(tk.END, f"✔ {header}: {headers[header]}\n", "ok")
            else:
                headers_text.insert(tk.END, f"❌ {header} não encontrado!\n", "error")
        
        custom_ports = port_entry.get().strip()
        if custom_ports:
            try:
                ports = [int(p.strip()) for p in custom_ports.split(",") if p.strip().isdigit()]
            except Exception:
                ports = [80, 443, 21, 22, 25, 3306]
        else:
            ports = [80, 443, 21, 22, 25, 3306]
        
        scan_mode = port_mode.get()
        domain = url.replace("https://", "").replace("http://", "").split('/')[0]
        results = scan_ports(domain, ports, scan_mode)
        result_text = headers_text.get(1.0, tk.END)
        save_to_history("[Headers & Port Scan]\n" + result_text)
    except Exception as e:
        messagebox.showerror("Erro", f"Erro ao acessar {url}: {e}")
    update_status("Concluído Headers & Port Scan.")

def scan_ports(host, ports, mode):
    headers_text.insert(tk.END, "\n[+] Escaneando portas abertas (paralelizado):\n")
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(scan_port_single, host, port, mode) for port in ports]
        for future in concurrent.futures.as_completed(futures):
            port, resultado, tag = future.result()
            headers_text.insert(tk.END, resultado, tag)

# 2. Identificação do Sistema Operacional (mantida, com tratamento de exceções)
def identify_target_os(target):
    update_status("Identificando Sistema Operacional do Alvo...")
    os_text.delete(1.0, tk.END)
    os_text.insert(tk.END, "[+] Identificando Sistema Operacional do Alvo:\n")
    try:
        ping_cmd = "ping"
        if platform.system().lower() == "windows":
            command = [ping_cmd, "-n", "1", target]
        else:
            command = [ping_cmd, "-c", "1", target]
        
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode == 0 and "ttl=" in result.stdout.lower():
            ttl = int(result.stdout.lower().split("ttl=")[1].split()[0])
            if ttl <= 64:
                os_guess = "Provavelmente Linux/Unix"
            elif ttl <= 128:
                os_guess = "Provavelmente Windows"
            else:
                os_guess = "Sistema operacional desconhecido"
            os_text.insert(tk.END, f"TTL: {ttl}\n{os_guess}\n")
        else:
            os_text.insert(tk.END, "Não foi possível determinar o TTL.\n")
        save_to_history("[Identificação de OS]\n" + os_text.get(1.0, tk.END))
    except FileNotFoundError:
        os_text.insert(tk.END, "Erro: Comando 'ping' não encontrado. Verifique se está instalado.\n", "error")
    except Exception as e:
        os_text.insert(tk.END, f"Erro ao identificar o SO do alvo: {e}\n", "error")
    update_status("Concluído Identificação de OS.")

# 3. Obter informações de IP
def get_ip():
    update_status("Obtendo informações de IP...")
    ip_text.delete(1.0, tk.END)
    try:
        interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        ip_info = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
        ip_address = ip_info['addr']
        netmask = ip_info['netmask']
        ip_text.insert(tk.END, f"Interface: {interface}\n")
        ip_text.insert(tk.END, f"Endereço IP: {ip_address}\n")
        ip_text.insert(tk.END, f"Máscara de Rede: {netmask}\n")
        save_to_history("[Endereço IP]\n" + ip_text.get(1.0, tk.END))
    except Exception as e:
        ip_text.insert(tk.END, f"Erro ao obter informações de IP: {e}\n", "error")
    update_status("Concluído Endereço IP.")

# 4. Verificação de SSL/TLS aprimorada
def check_ssl_cert():
    update_status("Verificando certificado SSL/TLS...")
    ssl_text.delete(1.0, tk.END)
    domain = ssl_entry.get().strip()
    if not domain:
        messagebox.showwarning("Aviso", "Digite um domínio.")
        return
    if not domain.startswith("https://") and not domain.startswith("http://"):
        domain = "https://" + domain
    domain_clean = domain.replace("https://", "").replace("http://", "")
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=domain_clean)
        conn.settimeout(5)
        conn.connect((domain_clean, 443))
        cert = conn.getpeercert()
        ssl_text.insert(tk.END, f"Certificado para {domain}:\n")
        notAfter = cert.get("notAfter", "N/A")
        ssl_text.insert(tk.END, f"Expira em: {notAfter}\n")
        subject = dict(x[0] for x in cert.get('subject', []))
        issuer = dict(x[0] for x in cert.get('issuer', []))
        if subject == issuer:
            ssl_text.insert(tk.END, "Certificado autoassinado.\n", "warn")
        conn.close()
        save_to_history("[SSL/TLS]\n" + ssl_text.get(1.0, tk.END))
    except Exception as e:
        ssl_text.insert(tk.END, f"Erro ao verificar SSL/TLS: {e}\n", "error")
    update_status("Concluído SSL/TLS Checker.")

# 5. Detector de Tecnologias Web (usa Wappalyzer se disponível)
def detect_technologies():
    update_status("Detectando tecnologias web...")
    tech_text.delete(1.0, tk.END)
    url = tech_entry.get().strip()
    if not url:
        messagebox.showwarning("Aviso", "Digite uma URL.")
        return
    try:
        if WAPPALYZER_AVAILABLE:
            webpage = WebPage.new_from_url(url)
            wappalyzer = Wappalyzer.latest()
            techs = wappalyzer.analyze(webpage)
            tech_text.insert(tk.END, f"Tecnologias detectadas com Wappalyzer:\n" + ", ".join(techs) + "\n")
        else:
            response = requests.get(url, timeout=5)
            tech_text.insert(tk.END, f"Analisando {url}\n")
            headers = response.headers
            found = []
            if "X-Powered-By" in headers:
                found.append(f"X-Powered-By: {headers['X-Powered-By']}")
            if "Server" in headers:
                found.append(f"Server: {headers['Server']}")
            content = response.text.lower()
            tech_signatures = {
                "WordPress": "wp-content",
                "Joomla": "joomla",
                "Drupal": "drupal",
                "Magento": "magento",
                "PrestaShop": "prestashop"
            }
            for tech, signature in tech_signatures.items():
                if signature.lower() in content:
                    found.append(tech)
            if found:
                tech_text.insert(tk.END, "Tecnologias detectadas:\n" + "\n".join(found) + "\n")
            else:
                tech_text.insert(tk.END, "Nenhuma tecnologia específica detectada.\n")
        save_to_history("[Tecnologias Web]\n" + tech_text.get(1.0, tk.END))
    except Exception as e:
        tech_text.insert(tk.END, f"Erro ao detectar tecnologias: {e}\n", "error")
    update_status("Concluído Detector de Tecnologias Web.")

# 6. Escaneamento de Subdomínios com opção de wordlist personalizada
def scan_subdomains():
    update_status("Escaneando subdomínios...")
    subdomain_text.delete(1.0, tk.END)
    domain = subdomain_entry.get().strip()
    if not domain:
        messagebox.showwarning("Aviso", "Digite um domínio.")
        return
    use_wordlist = messagebox.askyesno("Wordlist", "Deseja carregar uma wordlist personalizada para subdomínios?")
    if use_wordlist:
        wordlist_file = filedialog.askopenfilename(title="Selecione o arquivo de wordlist", filetypes=[("Text Files", "*.txt")])
        if wordlist_file:
            with open(wordlist_file, "r", encoding="utf-8") as f:
                common_subdomains = [line.strip() for line in f if line.strip()]
        else:
            common_subdomains = ["www", "mail", "ftp", "blog", "dev", "test", "ns1", "ns2"]
    else:
        common_subdomains = ["www", "mail", "ftp", "blog", "dev", "test", "ns1", "ns2"]
    found = []
    for sub in common_subdomains:
        full_domain = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(full_domain)
            found.append(f"{full_domain} -> {ip}")
        except Exception:
            pass
    if found:
        subdomain_text.insert(tk.END, "Subdomínios encontrados:\n" + "\n".join(found) + "\n")
    else:
        subdomain_text.insert(tk.END, "Nenhum subdomínio encontrado.\n")
    save_to_history("[Subdomínios]\n" + subdomain_text.get(1.0, tk.END))
    update_status("Concluído Escaneamento de Subdomínios.")

# 7. Teste de SQL Injection com vários payloads
def test_sql_injection():
    update_status("Testando SQL Injection...")
    sql_text.delete(1.0, tk.END)
    url = sql_entry.get().strip()
    if not url:
        messagebox.showwarning("Aviso", "Digite uma URL para teste.")
        return
    payloads = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "'--", "'#", "' OR '1'='1' -- "]
    vulnerable_payloads = []
    for payload in payloads:
        test_url = url + payload if "?" in url else url + "/" + payload
        try:
            response = requests.get(test_url, timeout=5)
            errors = ["sql syntax", "mysql", "ora-01756", "sqlstate"]
            if any(err in response.text.lower() for err in errors):
                vulnerable_payloads.append(payload)
                sql_text.insert(tk.END, f"Payload '{payload}' pode indicar vulnerabilidade!\n", "error")
            else:
                sql_text.insert(tk.END, f"Payload '{payload}' parece seguro.\n", "ok")
        except Exception as e:
            sql_text.insert(tk.END, f"Erro com payload '{payload}': {e}\n", "error")
    if vulnerable_payloads:
        sql_text.insert(tk.END, "\nPossível vulnerabilidade detectada com os payloads: " + ", ".join(vulnerable_payloads) + "\n", "error")
    else:
        sql_text.insert(tk.END, "\nNenhuma vulnerabilidade de SQL Injection detectada.\n", "ok")
    save_to_history("[SQL Injection]\n" + sql_text.get(1.0, tk.END))
    update_status("Concluído Teste de SQL Injection.")

# 8. Traceroute
def run_traceroute():
    update_status("Executando traceroute...")
    traceroute_text.delete(1.0, tk.END)
    target = traceroute_entry.get().strip()
    if not target:
        messagebox.showwarning("Aviso", "Digite um IP ou domínio.")
        return
    try:
        if platform.system().lower() == "windows":
            command = ["tracert", target]
        else:
            command = ["traceroute", target]
        result = subprocess.run(command, capture_output=True, text=True)
        traceroute_text.insert(tk.END, result.stdout)
        save_to_history("[Traceroute]\n" + result.stdout)
    except Exception as e:
        traceroute_text.insert(tk.END, f"Erro ao executar traceroute: {e}\n", "error")
    update_status("Concluído Traceroute.")

# 9. Geolocalização de IP
def geo_ip():
    update_status("Localizando IP...")
    geo_text.delete(1.0, tk.END)
    ip = geo_entry.get().strip()
    if not ip:
        messagebox.showwarning("Aviso", "Digite um IP.")
        return
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()
        if data["status"] == "success":
            info = (
                f"País: {data['country']}\n"
                f"Região: {data['regionName']}\n"
                f"Cidade: {data['city']}\n"
                f"ISP: {data['isp']}\n"
                f"Latitude: {data['lat']}\n"
                f"Longitude: {data['lon']}\n"
            )
            geo_text.insert(tk.END, info)
        else:
            geo_text.insert(tk.END, "Não foi possível localizar o IP.\n")
        save_to_history("[Geolocalização de IP]\n" + geo_text.get(1.0, tk.END))
    except Exception as e:
        geo_text.insert(tk.END, f"Erro ao localizar IP: {e}\n", "error")
    update_status("Concluído Geolocalização de IP.")

# 10. Exportar resultados para PDF (utilizando fpdf)
def export_all_pdf():
    update_status("Exportando para PDF...")
    if FPDF is None:
        messagebox.showerror("Erro", "Biblioteca fpdf não instalada.")
        update_status("Erro ao exportar PDF.")
        return
    filename = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF Files", "*.pdf")])
    if not filename:
        update_status("Exportação de PDF cancelada.")
        return
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    sections = [
        ("Headers & Port Scan", headers_text.get(1.0, tk.END)),
        ("Identificação de OS", os_text.get(1.0, tk.END)),
        ("Endereço IP", ip_text.get(1.0, tk.END)),
        ("SSL/TLS", ssl_text.get(1.0, tk.END)),
        ("Tecnologias Web", tech_text.get(1.0, tk.END)),
        ("Subdomínios", subdomain_text.get(1.0, tk.END)),
        ("SQL Injection", sql_text.get(1.0, tk.END)),
        ("Traceroute", traceroute_text.get(1.0, tk.END)),
        ("Geolocalização de IP", geo_text.get(1.0, tk.END)),
        ("Histórico", history_text.get(1.0, tk.END))
    ]
    for title, content in sections:
        pdf.add_page()
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, title, ln=True)
        pdf.set_font("Arial", "", 12)
        for line in content.splitlines():
            pdf.multi_cell(0, 10, line)
    try:
        pdf.output(filename)
        messagebox.showinfo("Sucesso", f"PDF exportado para {filename}")
    except Exception as e:
        messagebox.showerror("Erro", f"Erro ao exportar PDF: {e}")
    update_status("Concluído exportação para PDF.")

# 11. Alternar Tema (Modo Claro / Escuro)
def toggle_theme():
    global is_dark_mode
    is_dark_mode = not is_dark_mode
    if is_dark_mode:
        style.theme_use("clam")
        style.configure("TFrame", background="#2e2e2e")
        style.configure("TLabel", background="#2e2e2e", foreground="white")
        style.configure("TButton", background="#444444", foreground="white")
        style.configure("TNotebook", background="#2e2e2e")
        root.configure(background="#2e2e2e")
    else:
        style.theme_use("clam")
        style.configure("TFrame", background="#e6e6e6")
        style.configure("TLabel", background="#e6e6e6", foreground="black")
        style.configure("TButton", background="#e6e6e6", foreground="black")
        style.configure("TNotebook", background="#e6e6e6")
        root.configure(background="#e6e6e6")
    update_status("Tema alterado.")

def clear_text(widget):
    widget.delete(1.0, tk.END)

def save_results():
    filename = simpledialog.askstring("Salvar", "Digite o nome do arquivo:")
    if filename:
        with open(f"{filename}.txt", "w", encoding="utf-8") as file:
            file.write("[Headers & Port Scan]\n" + headers_text.get(1.0, tk.END) + "\n")
            file.write("[Identificação de OS]\n" + os_text.get(1.0, tk.END) + "\n")
            file.write("[Endereço IP]\n" + ip_text.get(1.0, tk.END) + "\n")
        messagebox.showinfo("Sucesso", f"Resultados salvos em {filename}.txt")

# ───────────────────────────────────────────────────────────────
# IMPLEMENTAÇÃO DO MODO CLI
def cli_mode():
    print("Modo CLI - Cybersecurity Toolkit")
    while True:
        print("\nSelecione uma opção:")
        print("1 - Headers & Port Scan")
        print("2 - Identificação de OS")
        print("3 - Obter Endereço IP")
        print("4 - Verificar SSL/TLS")
        print("5 - Detectar Tecnologias Web")
        print("6 - Escanear Subdomínios")
        print("7 - Testar SQL Injection")
        print("8 - Executar Traceroute")
        print("9 - Geolocalização de IP")
        print("0 - Sair")
        choice = input("Opção: ").strip()
        if choice == "1":
            url = input("Digite a URL do site (com https://): ").strip()
            if not (url.startswith("https://") or url.startswith("http://")):
                url = "https://" + url
            print("Realizando Headers & Port Scan...")
            try:
                response = requests.get(url, timeout=5)
                headers = response.headers
                print("[+] Cabeçalhos:")
                for k, v in headers.items():
                    print(f"{k}: {v}")
            except Exception as e:
                print(f"Erro: {e}")
        elif choice == "2":
            target = input("Digite o IP do alvo: ").strip()
            try:
                ping_cmd = "ping"
                if platform.system().lower() == "windows":
                    command = [ping_cmd, "-n", "1", target]
                else:
                    command = [ping_cmd, "-c", "1", target]
                result = subprocess.run(command, capture_output=True, text=True)
                if result.returncode == 0 and "ttl=" in result.stdout.lower():
                    ttl = int(result.stdout.lower().split("ttl=")[1].split()[0])
                    if ttl <= 64:
                        os_guess = "Provavelmente Linux/Unix"
                    elif ttl <= 128:
                        os_guess = "Provavelmente Windows"
                    else:
                        os_guess = "Sistema operacional desconhecido"
                    print(f"TTL: {ttl}\n{os_guess}")
                else:
                    print("Não foi possível determinar o TTL.")
            except Exception as e:
                print(f"Erro: {e}")
        elif choice == "3":
            try:
                interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
                ip_info = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
                ip_address = ip_info['addr']
                netmask = ip_info['netmask']
                print(f"Interface: {interface}")
                print(f"Endereço IP: {ip_address}")
                print(f"Máscara de Rede: {netmask}")
            except Exception as e:
                print(f"Erro ao obter informações de IP: {e}")
        elif choice == "4":
            domain = input("Digite o domínio (ex: example.com): ").strip()
            try:
                ctx = ssl.create_default_context()
                conn = ctx.wrap_socket(socket.socket(), server_hostname=domain)
                conn.settimeout(5)
                conn.connect((domain, 443))
                cert = conn.getpeercert()
                print(f"Certificado para {domain}:")
                print(f"Expira em: {cert.get('notAfter', 'N/A')}")
                conn.close()
            except Exception as e:
                print(f"Erro: {e}")
        elif choice == "5":
            url = input("Digite a URL do site (com https://): ").strip()
            try:
                if WAPPALYZER_AVAILABLE:
                    webpage = WebPage.new_from_url(url)
                    wappalyzer = Wappalyzer.latest()
                    techs = wappalyzer.analyze(webpage)
                    print("Tecnologias detectadas:", ", ".join(techs))
                else:
                    response = requests.get(url, timeout=5)
                    headers = response.headers
                    print("Cabeçalhos:", headers)
            except Exception as e:
                print(f"Erro: {e}")
        elif choice == "6":
            domain = input("Digite o domínio: ").strip()
            common_subdomains = ["www", "mail", "ftp", "blog", "dev", "test", "ns1", "ns2"]
            found = []
            for sub in common_subdomains:
                full_domain = f"{sub}.{domain}"
                try:
                    ip = socket.gethostbyname(full_domain)
                    found.append(f"{full_domain} -> {ip}")
                except Exception:
                    pass
            if found:
                print("Subdomínios encontrados:")
                for item in found:
                    print(item)
            else:
                print("Nenhum subdomínio encontrado.")
        elif choice == "7":
            url = input("Digite a URL para teste (com https://): ").strip()
            payloads = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "'--", "'#", "' OR '1'='1' -- "]
            for payload in payloads:
                test_url = url + payload if "?" in url else url + "/" + payload
                try:
                    response = requests.get(test_url, timeout=5)
                    errors = ["sql syntax", "mysql", "ora-01756", "sqlstate"]
                    if any(err in response.text.lower() for err in errors):
                        print(f"Payload '{payload}' pode indicar vulnerabilidade!")
                    else:
                        print(f"Payload '{payload}' parece seguro.")
                except Exception as e:
                    print(f"Erro com payload '{payload}': {e}")
        elif choice == "8":
            target = input("Digite o IP ou domínio para traceroute: ").strip()
            try:
                if platform.system().lower() == "windows":
                    command = ["tracert", target]
                else:
                    command = ["traceroute", target]
                result = subprocess.run(command, capture_output=True, text=True)
                print(result.stdout)
            except Exception as e:
                print(f"Erro: {e}")
        elif choice == "9":
            ip = input("Digite o IP: ").strip()
            try:
                response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
                data = response.json()
                if data["status"] == "success":
                    info = (
                        f"País: {data['country']}\n"
                        f"Região: {data['regionName']}\n"
                        f"Cidade: {data['city']}\n"
                        f"ISP: {data['isp']}\n"
                        f"Latitude: {data['lat']}\n"
                        f"Longitude: {data['lon']}\n"
                    )
                    print(info)
                else:
                    print("Não foi possível localizar o IP.")
            except Exception as e:
                print(f"Erro: {e}")
        elif choice == "0":
            print("Saindo...")
            break
        else:
            print("Opção inválida.")

# ───────────────────────────────────────────────────────────────
# MAIN: Verifica se o modo CLI foi solicitado
if __name__ == "__main__":
    if "--cli" in sys.argv:
        cli_mode()
    else:
        # CONFIGURAÇÃO DA INTERFACE GRÁFICA
        root = tk.Tk()
        root.title("Cybersecurity Toolkit")
        root.geometry("900x700")
        style = ttk.Style(root)
        style.theme_use("clam")
        style.configure("TNotebook", background="#e6e6e6", borderwidth=0)
        style.configure("TNotebook.Tab", font=("Helvetica", 12, "bold"), padding=[10, 5])
        style.configure("TFrame", background="#e6e6e6")
        style.configure("TButton", font=("Helvetica", 10))
        style.configure("TLabel", font=("Helvetica", 10))
        root.configure(background="#e6e6e6")
        status_var = tk.StringVar()
        status_var.set("Pronto.")
        status_bar = ttk.Label(root, textvariable=status_var, relief=tk.SUNKEN, anchor="w")
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        notebook = ttk.Notebook(root)
        notebook.pack(pady=10, expand=True, fill='both')
        # Tab: Headers & Port Scan
        frame_headers = ttk.Frame(notebook)
        notebook.add(frame_headers, text="Headers & Port Scan")
        input_frame = ttk.Frame(frame_headers, padding=10)
        input_frame.pack(pady=5, fill='x')
        ttk.Label(input_frame, text="Digite a URL do site:").pack(side=tk.LEFT, padx=(0, 5))
        url_entry = ttk.Entry(input_frame, width=50)
        url_entry.pack(side=tk.LEFT, padx=(0, 5))
        url_entry.insert(0, "https://")
        ttk.Label(input_frame, text="Portas (ex: 80,443):").pack(side=tk.LEFT, padx=(10, 5))
        port_entry = ttk.Entry(input_frame, width=20)
        port_entry.pack(side=tk.LEFT, padx=(0, 5))
        port_mode = tk.StringVar(value="Rápido")
        ttk.Radiobutton(input_frame, text="Rápido", variable=port_mode, value="Rápido").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(input_frame, text="Detalhado", variable=port_mode, value="Detalhado").pack(side=tk.LEFT, padx=5)
        ttk.Button(input_frame, text="Escanear", command=lambda: check_headers_and_scan_ports(url_entry.get())).pack(side=tk.LEFT, padx=10)
        headers_text = scrolledtext.ScrolledText(frame_headers, width=100, height=15, font=("Consolas", 10))
        headers_text.pack(pady=5, padx=10, fill='both', expand=True)
        headers_text.tag_config("ok", foreground="green")
        headers_text.tag_config("error", foreground="red")
        headers_text.tag_config("warn", foreground="orange")
        button_frame_headers = ttk.Frame(frame_headers, padding=10)
        button_frame_headers.pack(fill='x')
        ttk.Button(button_frame_headers, text="Limpar", command=lambda: clear_text(headers_text)).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame_headers, text="Salvar Resultados", command=save_results).pack(side=tk.LEFT, padx=5)
        # Tab: Identificar OS
        frame_os = ttk.Frame(notebook)
        notebook.add(frame_os, text="Identificar OS")
        os_input_frame = ttk.Frame(frame_os, padding=10)
        os_input_frame.pack(pady=5, fill='x')
        ttk.Label(os_input_frame, text="Digite o IP do Alvo:").pack(side=tk.LEFT, padx=(0, 5))
        os_entry = ttk.Entry(os_input_frame, width=50)
        os_entry.pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(os_input_frame, text="Identificar OS do Alvo", command=lambda: identify_target_os(os_entry.get())).pack(side=tk.LEFT, padx=5)
        os_text = scrolledtext.ScrolledText(frame_os, width=100, height=15, font=("Consolas", 10))
        os_text.pack(pady=5, padx=10, fill='both', expand=True)
        ttk.Button(frame_os, text="Limpar", command=lambda: clear_text(os_text)).pack(pady=5)
        # Tab: Endereço IP
        frame_ip = ttk.Frame(notebook)
        notebook.add(frame_ip, text="Endereço IP")
        ip_button_frame = ttk.Frame(frame_ip, padding=10)
        ip_button_frame.pack(pady=5, fill='x')
        ttk.Button(ip_button_frame, text="Obter IP", command=get_ip).pack(side=tk.LEFT, padx=5)
        ip_text = scrolledtext.ScrolledText(frame_ip, width=100, height=15, font=("Consolas", 10))
        ip_text.pack(pady=5, padx=10, fill='both', expand=True)
        ttk.Button(frame_ip, text="Limpar", command=lambda: clear_text(ip_text)).pack(pady=5)
        # Tab: SSL/TLS Checker
        frame_ssl = ttk.Frame(notebook)
        notebook.add(frame_ssl, text="SSL/TLS")
        ssl_input_frame = ttk.Frame(frame_ssl, padding=10)
        ssl_input_frame.pack(pady=5, fill='x')
        ttk.Label(ssl_input_frame, text="Digite o domínio:").pack(side=tk.LEFT, padx=(0, 5))
        ssl_entry = ttk.Entry(ssl_input_frame, width=50)
        ssl_entry.pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(ssl_input_frame, text="Verificar SSL/TLS", command=check_ssl_cert).pack(side=tk.LEFT, padx=5)
        ssl_text = scrolledtext.ScrolledText(frame_ssl, width=100, height=15, font=("Consolas", 10))
        ssl_text.pack(pady=5, padx=10, fill='both', expand=True)
        ttk.Button(frame_ssl, text="Limpar", command=lambda: clear_text(ssl_text)).pack(pady=5)
        # Tab: Tecnologias Web
        frame_tech = ttk.Frame(notebook)
        notebook.add(frame_tech, text="Tecnologias Web")
        tech_input_frame = ttk.Frame(frame_tech, padding=10)
        tech_input_frame.pack(pady=5, fill='x')
        ttk.Label(tech_input_frame, text="Digite a URL do site:").pack(side=tk.LEFT, padx=(0, 5))
        tech_entry = ttk.Entry(tech_input_frame, width=50)
        tech_entry.pack(side=tk.LEFT, padx=(0, 5))
        tech_entry.insert(0, "https://")
        ttk.Button(tech_input_frame, text="Detectar Tecnologias", command=detect_technologies).pack(side=tk.LEFT, padx=5)
        tech_text = scrolledtext.ScrolledText(frame_tech, width=100, height=15, font=("Consolas", 10))
        tech_text.pack(pady=5, padx=10, fill='both', expand=True)
        ttk.Button(frame_tech, text="Limpar", command=lambda: clear_text(tech_text)).pack(pady=5)
        # Tab: Subdomínios
        frame_subdomain = ttk.Frame(notebook)
        notebook.add(frame_subdomain, text="Subdomínios")
        subdomain_input_frame = ttk.Frame(frame_subdomain, padding=10)
        subdomain_input_frame.pack(pady=5, fill='x')
        ttk.Label(subdomain_input_frame, text="Digite o domínio:").pack(side=tk.LEFT, padx=(0, 5))
        subdomain_entry = ttk.Entry(subdomain_input_frame, width=50)
        subdomain_entry.pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(subdomain_input_frame, text="Escanear Subdomínios", command=scan_subdomains).pack(side=tk.LEFT, padx=5)
        subdomain_text = scrolledtext.ScrolledText(frame_subdomain, width=100, height=15, font=("Consolas", 10))
        subdomain_text.pack(pady=5, padx=10, fill='both', expand=True)
        ttk.Button(frame_subdomain, text="Limpar", command=lambda: clear_text(subdomain_text)).pack(pady=5)
        # Tab: SQL Injection
        frame_sql = ttk.Frame(notebook)
        notebook.add(frame_sql, text="SQL Injection")
        sql_input_frame = ttk.Frame(frame_sql, padding=10)
        sql_input_frame.pack(pady=5, fill='x')
        ttk.Label(sql_input_frame, text="Digite a URL para teste:").pack(side=tk.LEFT, padx=(0, 5))
        sql_entry = ttk.Entry(sql_input_frame, width=50)
        sql_entry.pack(side=tk.LEFT, padx=(0, 5))
        sql_entry.insert(0, "https://")
        ttk.Button(sql_input_frame, text="Testar SQL Injection", command=test_sql_injection).pack(side=tk.LEFT, padx=5)
        sql_text = scrolledtext.ScrolledText(frame_sql, width=100, height=15, font=("Consolas", 10))
        sql_text.pack(pady=5, padx=10, fill='both', expand=True)
        sql_text.tag_config("ok", foreground="green")
        sql_text.tag_config("error", foreground="red")
        ttk.Button(frame_sql, text="Limpar", command=lambda: clear_text(sql_text)).pack(pady=5)
        # Tab: Traceroute
        frame_traceroute = ttk.Frame(notebook)
        notebook.add(frame_traceroute, text="Traceroute")
        traceroute_input_frame = ttk.Frame(frame_traceroute, padding=10)
        traceroute_input_frame.pack(pady=5, fill='x')
        ttk.Label(traceroute_input_frame, text="Digite o IP ou domínio:").pack(side=tk.LEFT, padx=(0, 5))
        traceroute_entry = ttk.Entry(traceroute_input_frame, width=50)
        traceroute_entry.pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(traceroute_input_frame, text="Executar Traceroute", command=run_traceroute).pack(side=tk.LEFT, padx=5)
        traceroute_text = scrolledtext.ScrolledText(frame_traceroute, width=100, height=15, font=("Consolas", 10))
        traceroute_text.pack(pady=5, padx=10, fill='both', expand=True)
        ttk.Button(frame_traceroute, text="Limpar", command=lambda: clear_text(traceroute_text)).pack(pady=5)
        # Tab: Geolocalização de IP
        frame_geo = ttk.Frame(notebook)
        notebook.add(frame_geo, text="Geolocalização de IP")
        geo_input_frame = ttk.Frame(frame_geo, padding=10)
        geo_input_frame.pack(pady=5, fill='x')
        ttk.Label(geo_input_frame, text="Digite o IP:").pack(side=tk.LEFT, padx=(0, 5))
        geo_entry = ttk.Entry(geo_input_frame, width=50)
        geo_entry.pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(geo_input_frame, text="Localizar IP", command=geo_ip).pack(side=tk.LEFT, padx=5)
        geo_text = scrolledtext.ScrolledText(frame_geo, width=100, height=15, font=("Consolas", 10))
        geo_text.pack(pady=5, padx=10, fill='both', expand=True)
        ttk.Button(frame_geo, text="Limpar", command=lambda: clear_text(geo_text)).pack(pady=5)
        # Tab: Histórico
        frame_history = ttk.Frame(notebook)
        notebook.add(frame_history, text="Histórico")
        history_text = scrolledtext.ScrolledText(frame_history, width=100, height=15, font=("Consolas", 10))
        history_text.pack(pady=5, padx=10, fill='both', expand=True)
        def refresh_history():
            history_text.delete(1.0, tk.END)
            history_text.insert(tk.END, load_history())
        history_button_frame = ttk.Frame(frame_history, padding=10)
        history_button_frame.pack(fill='x')
        ttk.Button(history_button_frame, text="Atualizar Histórico", command=refresh_history).pack(side=tk.LEFT, padx=5)
        ttk.Button(history_button_frame, text="Limpar Histórico", command=clear_history).pack(side=tk.LEFT, padx=5)
        # Menu
        menu_bar = tk.Menu(root)
        theme_menu = tk.Menu(menu_bar, tearoff=0)
        theme_menu.add_command(label="Alternar Modo Escuro", command=toggle_theme)
        menu_bar.add_cascade(label="Tema", menu=theme_menu)
        menu_bar.add_command(label="Exportar PDF", command=export_all_pdf)
        root.config(menu=menu_bar)
        root.mainloop()
