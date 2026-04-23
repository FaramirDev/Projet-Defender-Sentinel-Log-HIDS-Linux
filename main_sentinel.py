import time
import re
import os
import json
import requests
from datetime import datetime
from dotenv import load_dotenv

## CARTOUCHE - Sentinel-Log 
# Autheur : Alexis Rousseau - Ingenieur | Admin Systeme Reseau et Cybersécurité
# mail : alexisrousseau.work@proton.me
# Date : 23/04/2026
# Vesion : v2.1 
# --
# Description : Sentinel est un outil d'Audit de Monitoring en temps reel avec suivi complet des logs de connexion au syteme 
# Gestion des Acces avec une whitelist /data/whitelist.json | Tracabilité | Ban automatique avec Seuil sur le noyaux - iptable
# --
# Remonte des ensembles des alertes ( Acces | BAN ) sur serveur Discord 
# Tracabilité via une DATA centralisé sur /data/data_ip.json 
# Tracabilité unique par action /logs avec [IP]_acces_[DATE].json | [IP]_echec_[DATE].json | [IP]_banned_[DATE].json
# Script sous licence CC BY-NC 4.0

## --- PARTIE 1 - CONFIGURATION ---
os.chdir(os.path.dirname(os.path.abspath(__file__)))
load_dotenv()

PATH_LOG_AUTH = "/var/log/auth.log"
PATH_WHITELIST = "data/whitelist.json"
PATH_DATA_IP = "data/data_ip.json"
PATH_LOGS = "logs/"
WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")

# Init dossiers
os.makedirs("data", exist_ok=True)
os.makedirs("logs", exist_ok=True)

## --- PARTIE 2 : OUTILS SYSTÈME & JSON ---

def apply_permissions(path):
    uid = int(os.environ.get('SUDO_UID', 0))
    gid = int(os.environ.get('SUDO_GID', 0))
    if uid != 0:
        try:
            os.chown(path, uid, gid)
            os.chmod(path, 0o644)
        except: pass

def load_json(path, default):
    if os.path.exists(path):
        with open(path, 'r') as f:
            try: return json.load(f)
            except: return default
    return default

def save_json(path, data):
    with open(path, 'w') as f:
        json.dump(data, f, indent=4)
    apply_permissions(path)

# --- PARTIE 3 : LOGS GRANULAIRES & ALERTES ---

def write_individual_log(ip, status, user_target):
    """ Crée un fichier JSON unique pour l'événement """
    now = datetime.now()
    timestamp_file = now.strftime("%Y-%m-%d_%H-%M-%S")
    timestamp_full = now.strftime("%Y-%m-%d %H:%M:%S")
    
    # Nom du fichier : [ip]_[status]_[date-heure-min-sec].json
    filename = f"{PATH_LOGS}{ip}_{status}_{timestamp_file}.json"
    
    event_data = {
        "event_type": status,
        "ip_source": ip,
        "user_target": user_target,
        "full_timestamp": timestamp_full,
        "system_log_source": PATH_LOG_AUTH
    }
    
    save_json(filename, event_data)
    apply_permissions(filename)

    print(f"📄 Log individuel généré : {filename}")

def send_discord_alert(message, color=15158332):
    if not WEBHOOK_URL: return
    payload = {
        "embeds": [{
            "title": "🛡️ Sentinel-Log Alert",
            "description": message,
            "color": color,
            "timestamp": datetime.now().isoformat()
        }]
    }
    try: requests.post(WEBHOOK_URL, json=payload)
    except: print("❌ Erreur d'envoi Discord")

def ban_ip(ip, user):
    print(f"🔨 [PARE-FEU] Bannissement de {ip}...")
    if os.system(f"sudo iptables -A INPUT -s {ip} -j DROP") == 0:
        msg = f"🚫 **BANNISSEMENT DÉFINITIF**\n**IP :** `{ip}`\n**Raison :** Seuil de 3 tentatives atteint."
        send_discord_alert(msg, color=15158332)
        write_individual_log(ip, "banned", user)
        return True
    return False

# --- PARTIE 4 : ANALYSE DES LOGS ---

def extract_event(line):
    fail_match = re.search(r"Failed password for (?:invalid user )?(\w+) from ([\d\.]+)", line)
    if fail_match:
        return {"type": "echec", "user": fail_match.group(1), "ip": fail_match.group(2)}
    
    success_match = re.search(r"Accepted password for (\w+) from ([\d\.]+)", line)
    if success_match:
        return {"type": "succes", "user": success_match.group(1), "ip": success_match.group(2)}
    return None

# --- PARTIE 5 : BOUCLE PRINCIPALE ---

def main():
    print(f"🛡️ Sentinel-Log v2.1 (Granular Logging) démarré...")
    data_ip = load_json(PATH_DATA_IP, {})
    whitelist_data = load_json(PATH_WHITELIST, {"whitelist": {"local": "127.0.0.1"}})
    whitelist_ips = whitelist_data.get("whitelist", {}).values()

    with open(PATH_LOG_AUTH, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            
            event = extract_event(line)
            if not event: continue

            ip, user, ev_type = event["ip"], event["user"], event["type"]

            if ev_type == "succes":
                print(f"🔓 [ACCESS] {user} connecté depuis {ip}")
                send_discord_alert(f"✅ **CONNEXION RÉUSSIE**\n**User :** `{user}`\n**IP :** `{ip}`", color=3066993)
                write_individual_log(ip, "succes", user)
                continue

            if ip in whitelist_ips: 
                print(f"ℹ️ [WHITELIST] Tentative ignorée pour {ip}")
                continue

            # Gestion des échecs avec Data Complète
            if ip not in data_ip:
                data_ip[ip] = {
                    "tentatives": 0,
                    "first_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "status": "surveillance"
                }

            data_ip[ip]["tentatives"] += 1
            data_ip[ip]["last_attempt"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            data_ip[ip]["last_user_targeted"] = user
            nb = data_ip[ip]["tentatives"]
            
            save_json(PATH_DATA_IP, data_ip)

            if nb < 3:
                print(f"⚠️ [ALERT] Échec {nb}/3 - IP: {ip}")
                write_individual_log(ip, "echec", user)
            elif nb == 3:
                if ban_ip(ip, user):
                    data_ip[ip]["status"] = "BANNED"
                    save_json(PATH_DATA_IP, data_ip)

if __name__ == "__main__":
    main()