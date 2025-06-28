#!/usr/bin/env python3
"""
Outil de Reconnaissance Réseau Avancé
Conçu pour l'apprentissage de la cybersécurité
Utilisation: python network_recon.py
"""

import socket
import subprocess
import platform
import threading
import requests
import time
import datetime
import os
import re
from concurrent.futures import ThreadPoolExecutor

class NetworkRecon:
    def __init__(self):
        self.invalid_domains = 0
        self.max_invalid = 3
        self.common_ports = [22, 80, 443, 3306, 21, 25, 53, 110, 143, 993, 995]
        self.subdomains = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'api', 'blog', 'shop']
        
    def banner(self):
        """Affiche la bannière du programme"""
        print("\n" + "="*60)
        print("🔍 OUTIL DE RECONNAISSANCE RÉSEAU AVANCÉ 🔍")
        print("="*60)
        print("📚 Conçu pour l'apprentissage de la cybersécurité")
        print("⚠️  Usage éducatif uniquement - Respectez les lois locales")
        print("="*60 + "\n")

    def resolve_ip(self, domain):
        """Résout l'adresse IP d'un domaine"""
        try:
            ip = socket.gethostbyname(domain)
            print(f"✅ Résolution DNS: {domain} → {ip}")
            return ip
        except socket.gaierror:
            print(f"❌ Impossible de résoudre: {domain}")
            return None

    def reverse_dns(self, ip):
        """Effectue une résolution DNS inverse"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            print(f"🔄 DNS Inverse: {ip} → {hostname}")
            return hostname
        except socket.herror:
            print(f"🔄 DNS Inverse: Aucun nom trouvé pour {ip}")
            return None

    def ping_host(self, host):
        """Ping un hôte 3 fois et calcule le taux de réussite"""
        print(f"📡 Test de connectivité vers {host}...")
        
        param = "-n" if platform.system().lower() == "windows" else "-c"
        success_count = 0
        
        for i in range(3):
            try:
                result = subprocess.run(
                    ["ping", param, "1", host], 
                    capture_output=True, 
                    text=True, 
                    timeout=5
                )
                if result.returncode == 0:
                    success_count += 1
                    print(f"  Ping {i+1}/3: ✅ Réussi")
                else:
                    print(f"  Ping {i+1}/3: ❌ Échec")
            except subprocess.TimeoutExpired:
                print(f"  Ping {i+1}/3: ⏰ Timeout")
        
        success_rate = (success_count / 3) * 100
        print(f"📊 Taux de réussite: {success_rate:.1f}% ({success_count}/3)")
        return success_rate

    def analyze_ttl(self, host):
        """Analyse le TTL pour deviner le système d'exploitation"""
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(["ping", "-n", "1", host], capture_output=True, text=True)
                ttl_match = re.search(r'TTL=(\d+)', result.stdout)
            else:
                result = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True)
                ttl_match = re.search(r'ttl=(\d+)', result.stdout)
            
            if ttl_match:
                ttl = int(ttl_match.group(1))
                print(f"🔍 TTL détecté: {ttl}")
                
                if ttl <= 64:
                    os_guess = "Linux/Unix"
                elif ttl <= 128:
                    os_guess = "Windows"
                else:
                    os_guess = "Cisco/Réseau"
                    
                print(f"🖥️  Système probable: {os_guess}")
                return ttl, os_guess
        except:
            print("⚠️  Impossible d'analyser le TTL")
        return None, "Inconnu"

    def scan_port(self, ip, port, timeout=3):
        """Scan un port spécifique"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False

    def get_banner(self, ip, port):
        """Tente de récupérer la bannière d'un service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            
            # Envoie une requête basique selon le port
            if port == 80:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            elif port == 21:
                pass  # FTP envoie sa bannière automatiquement
            elif port == 22:
                pass  # SSH envoie sa bannière automatiquement
            elif port == 25:
                pass  # SMTP envoie sa bannière automatiquement
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            if banner:
                return banner[:100] + "..." if len(banner) > 100 else banner
        except:
            pass
        return None

    def port_scan(self, ip, ports):
        """Scan multiple ports avec threading"""
        print(f"🔍 Scan des ports sur {ip}...")
        open_ports = []
        
        def scan_single_port(port):
            if self.scan_port(ip, port):
                open_ports.append(port)
                banner = self.get_banner(ip, port)
                banner_info = f" - {banner}" if banner else ""
                print(f"  ✅ Port {port}/tcp OUVERT{banner_info}")
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(scan_single_port, ports)
        
        if not open_ports:
            print("  ❌ Aucun port ouvert détecté")
        
        return open_ports

    def http_check(self, domain, ip):
        """Vérifie les services HTTP/HTTPS"""
        services = {}
        
        # Test HTTP
        try:
            response = requests.get(f"http://{domain}", timeout=5, allow_redirects=False)
            services['http'] = {
                'status': response.status_code,
                'headers': dict(response.headers),
                'redirect': response.headers.get('Location', 'Non')
            }
            print(f"🌐 HTTP: Status {response.status_code}")
        except:
            print("🌐 HTTP: Non accessible")
        
        # Test HTTPS
        try:
            response = requests.get(f"https://{domain}", timeout=5, allow_redirects=False, verify=False)
            services['https'] = {
                'status': response.status_code,
                'headers': dict(response.headers)
            }
            print(f"🔒 HTTPS: Status {response.status_code}")
        except:
            print("🔒 HTTPS: Non accessible")
        
        return services

    def subdomain_scan(self, domain):
        """Scan des sous-domaines courants"""
        print(f"🔍 Scan des sous-domaines de {domain}...")
        found_subdomains = []
        
        def check_subdomain(sub):
            subdomain = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(subdomain)
                found_subdomains.append((subdomain, ip))
                print(f"  ✅ {subdomain} → {ip}")
            except:
                pass
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(check_subdomain, self.subdomains)
        
        if not found_subdomains:
            print("  ❌ Aucun sous-domaine trouvé")
        
        return found_subdomains

    def ascii_port_graph(self, open_ports):
        """Génère un graphique ASCII des ports ouverts"""
        if not open_ports:
            return "Aucun port ouvert à afficher"
        
        graph = "\n📊 GRAPHIQUE ASCII DES PORTS OUVERTS\n"
        graph += "=" * 40 + "\n"
        
        for port in sorted(open_ports):
            service_name = {
                21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS",
                80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
                993: "IMAPS", 995: "POP3S", 3306: "MySQL"
            }.get(port, "Unknown")
            
            bar_length = min(port // 100, 20)
            bar = "█" * bar_length + "░" * (20 - bar_length)
            graph += f"{port:>5} {service_name:<8} |{bar}|\n"
        
        graph += "=" * 40
        return graph

    def generate_report(self, domain, data):
        """Génère un rapport détaillé"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"rapport_{domain}_{timestamp}.txt"
        
        report = f"""
RAPPORT DE RECONNAISSANCE RÉSEAU
================================
Domaine analysé: {domain}
Date/Heure: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
================================

RÉSOLUTION DNS:
- Adresse IP: {data.get('ip', 'Non résolu')}
- DNS Inverse: {data.get('reverse_dns', 'Non trouvé')}

CONNECTIVITÉ:
- Taux de ping: {data.get('ping_rate', 0)}%
- TTL: {data.get('ttl', 'Non détecté')}
- Système probable: {data.get('os_guess', 'Inconnu')}

PORTS OUVERTS:
{', '.join(map(str, data.get('open_ports', []))) if data.get('open_ports') else 'Aucun'}

SERVICES WEB:
- HTTP: {data.get('http_status', 'Non accessible')}
- HTTPS: {data.get('https_status', 'Non accessible')}

SOUS-DOMAINES TROUVÉS:
{chr(10).join([f"- {sub} → {ip}" for sub, ip in data.get('subdomains', [])]) if data.get('subdomains') else 'Aucun'}

GRAPHIQUE DES PORTS:
{data.get('port_graph', 'N/A')}

================================
Fin du rapport
        """
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"📄 Rapport sauvegardé: {filename}")
        except Exception as e:
            print(f"❌ Erreur lors de la sauvegarde: {e}")
        
        return filename

    def update_history(self, domain, data):
        """Met à jour l'historique global"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            with open("historique.txt", "a", encoding='utf-8') as f:
                f.write(f"\n[{timestamp}] Analyse de {domain}\n")
                f.write(f"IP: {data.get('ip', 'N/A')} | ")
                f.write(f"Ports ouverts: {len(data.get('open_ports', []))} | ")
                f.write(f"Ping: {data.get('ping_rate', 0)}%\n")
                f.write("-" * 50 + "\n")
        except Exception as e:
            print(f"⚠️  Erreur historique: {e}")

    def analyze_domain(self, domain):
        """Analyse complète d'un domaine"""
        print(f"\n🎯 ANALYSE DE: {domain}")
        print("=" * 50)
        
        data = {}
        
        # Résolution IP
        ip = self.resolve_ip(domain)
        if not ip:
            return False
        data['ip'] = ip
        
        # DNS Inverse
        reverse = self.reverse_dns(ip)
        data['reverse_dns'] = reverse
        
        # Ping
        ping_rate = self.ping_host(domain)
        data['ping_rate'] = ping_rate
        
        # Analyse TTL
        ttl, os_guess = self.analyze_ttl(domain)
        data['ttl'] = ttl
        data['os_guess'] = os_guess
        
        # Scan des ports
        open_ports = self.port_scan(ip, self.common_ports)
        data['open_ports'] = open_ports
        
        # Vérification HTTP/HTTPS
        http_services = self.http_check(domain, ip)
        data['http_status'] = http_services.get('http', {}).get('status', 'N/A')
        data['https_status'] = http_services.get('https', {}).get('status', 'N/A')
        
        # Scan sous-domaines
        subdomains = self.subdomain_scan(domain)
        data['subdomains'] = subdomains
        
        # Graphique ASCII
        port_graph = self.ascii_port_graph(open_ports)
        data['port_graph'] = port_graph
        print(port_graph)
        
        # Génération du rapport
        self.generate_report(domain, data)
        self.update_history(domain, data)
        
        print(f"\n✅ Analyse de {domain} terminée!")
        return True

    def validate_domain(self, domain):
        """Valide le format du domaine"""
        pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-_.]*[a-zA-Z0-9]$'
        return bool(re.match(pattern, domain)) and len(domain) > 1

    def run(self):
        """Boucle principale du programme"""
        self.banner()
        
        while True:
            try:
                domain = input("\n🔍 Entrez un domaine à analyser (ou 'exit' pour quitter): ").strip()
                
                if domain.lower() == 'exit':
                    print("\n👋 Merci d'avoir utilisé l'outil de reconnaissance!")
                    print("📚 N'oubliez pas: utilisez ces connaissances de manière éthique!")
                    break
                
                if not domain:
                    continue
                
                if not self.validate_domain(domain):
                    self.invalid_domains += 1
                    print(f"❌ Domaine invalide! ({self.invalid_domains}/{self.max_invalid})")
                    
                    if self.invalid_domains >= self.max_invalid:
                        print("🔒 Trop de domaines invalides. Arrêt du programme pour sécurité.")
                        break
                    continue
                
                # Reset du compteur après un domaine valide
                if self.analyze_domain(domain):
                    self.invalid_domains = 0
                
            except KeyboardInterrupt:
                print("\n\n⚡ Interruption détectée. Arrêt du programme...")
                break
            except Exception as e:
                print(f"❌ Erreur inattendue: {e}")

if __name__ == "__main__":
    # Vérification des dépendances
    try:
        import requests
    except ImportError:
        print("❌ Module 'requests' manquant. Installez-le avec: pip install requests")
        exit(1)
    
    # Lancement du programme
    recon = NetworkRecon()
    recon.run()