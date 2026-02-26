import re
import requests
from collections import defaultdict

# O ficheiro que vamos analisar
FICHEIRO_LOG = "mock_auth.log"

def obter_pais(ip):
    """Consulta uma API gratuita para descobrir o país de um IP."""
    try:
        # Faz um pedido GET à API
        resposta = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        dados = resposta.json()
        
        # Verifica se a API conseguiu encontrar o IP
        if dados.get("status") == "success":
            return dados.get("country")
        return "Desconhecido/Local"
    except Exception:
        return "Erro de Conexão"

def analisar_logs():
    tentativas_ip = defaultdict(int)
    padrao_regex = r"Failed password for .* from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"
    
    print("[*] A iniciar o Mini-SIEM (com Threat Intelligence)...")
    print(f"[*] A analisar o ficheiro de logs: {FICHEIRO_LOG}\n")
    
    try:
        with open(FICHEIRO_LOG, "r") as ficheiro:
            for linha in ficheiro:
                match = re.search(padrao_regex, linha)
                if match:
                    ip_atacante = match.group(1)
                    tentativas_ip[ip_atacante] += 1
                    
        print("=== RELATÓRIO DE AMEAÇAS (BRUTE-FORCE) ===")
        if not tentativas_ip:
            print("[+] Sistema seguro. Nenhum ataque detetado.")
        else:
            print("[*] A enriquecer dados com localização geográfica... aguarda.\n")
            for ip, contagem in tentativas_ip.items():
                # Aqui chamamos a API para cada IP malicioso encontrado
                pais = obter_pais(ip)
                
                if contagem >= 3:
                    print(f"[ALERTA VERMELHO] Bloquear IP: {ip} ({pais}) - {contagem} tentativas falhadas!")
                else:
                    print(f"[AVISO] IP Suspeito: {ip} ({pais}) - {contagem} tentativas falhadas.")
                    
    except FileNotFoundError:
        print(f"[-] Erro: Ficheiro {FICHEIRO_LOG} não encontrado.")

if __name__ == "__main__":
    analisar_logs()
