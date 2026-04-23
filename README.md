# 🛡️ Sentinel-Log : HIDS & Défense Active SSH
## 1. Présentation
**Sentinel-Log** est un Système de **Détection** et de **Prévention** d'Intrusions **(HIDS/IPS)** léger écrit en **Python**. Il sécurise l'accès **SSH** en analysant en **temps réel** les flux d'authentification, en **bannissant** les attaquants via le pare-feu noyau et en offrant une **traçabilité** complète de chaque événement.

---
---
## ⛓️ 2. Fonctionnalités Clés
- **Analyse Temps Réel** : Monitoring du flux `/var/log/auth.log` via un générateur non-bloquant.

- **Détection Bimodale** : Identification des tentatives de **Brute-Force** ET des connexions **réussies**.

- **Défense Active** : Automatisation des règles de **bannissement** iptables (politique DROP).

- **Traçabilité Granulaire (Boîte Noire)** : Génération d'un fichier **JSON** unique par événement (echec/succes/banned) pour l'**audit** forensique.

- **Persistance des Données** : Base d'état JSON pour conserver l'**historique** des **attaquants** entre les redémarrages.

- **Alerting Discord** : Notifications **temps réel** avec codes couleurs (Vert pour accès, Rouge pour menace).

- **Sécurité des Secrets** : Intégration de python-dotenv pour la gestion des Webhooks.

---
---
## ⚙️ 3. Architecture & Démarche
- **Extraction** : Utilisation d'expressions régulières (**Regex**) pour capturer les tuples (User, IP) dans les logs système.

- **Filtrage** : Comparaison avec une **Whitelist** dynamique (dictionnaire JSON) pour protéger les accès administrateurs.

- **Réaction** : Dès le 3ème échec, l'IP est **bannie** et l'incident est logué.

- **Permissions** : Gestion **automatique** du chown/chmod pour permettre la lecture des rapports par l'utilisateur non-root.

---
---
## 🧿 4. Demonstration 
### Partie - 4.1. Remonté Automatique des Alertes sur le Serveur Discord
![Captures remonte alerte automatique 01](./captures/capture_remonte_discord_01.png)

---
### Partie - 4.2. Tracabilité de chaque action dans `/logs`
![Capture ecriture log 01](./captures/capture_log_01.png)

#### ● Exemple de sortie : 🟢 Succes
![Capture log Succes](./captures/capture_log_acces_01.png)

#### ●  Exemple de sortie : 🟠 Echec
![Capture log Echec](./captures/capture_log_echec_01.png)


#### ●  Exemple de sortie : 🔴 Banned
![Capture log Banned](./captures/capture_log_banned_01.png)

----
### Partie - 4.3. Tracabilité Global avec `data_ip` de toutes les Tentatives & Ban
#### ●  Exemple de sortie : data_ip
![Capture data_ip](./captures/capture_data_ip_STAT_01.png)

- **Changement** de Status en fonction de l'état : "*surveillance*" -> "*banned*" 

---
### Partie - 4.4. Banne automatique via iptable
- **Avantage** : le Paquet est directement **rejeté** par **DROP** par le noyaud avant d'arrivé sur le service ssh

![Capture banned iptable](./captures/rule_add_banned.png)

---
### Partie - 4.5. Comparaison via une `data/whitelist` pour authorisé certaine ip *(type admin)* 

#### ●  Exemple de fichier `/whitelist.json`
```json
{
    "whitelist" : {
        "local" : "127.0.0.1" 
    }
```

---
---
## 🕵️ 5. Installation en tant que Service (Systemd)
Pour garantir une protection 24/7, **Sentinel-Log** est déployé comme **démon** système :

- une fois le démon configuré : 

```
Bash
# Activation du service
sudo systemctl daemon-reload
sudo systemctl enable sentinel-log.service
sudo systemctl start sentinel-log.service
```

![Capture service sentinel log deployé](./captures/capture_system_sentinel.png)

## Consultation des journaux de fonctionnement
```
bash
journalctl -u sentinel-log.service -f
```

---
---
## 📂 Structure des Données
- `data/data_ip.json` : Base de données d'état (Compteurs, dates, statuts).

- `data/whitelist.json`: Dictionnaire des IP autorisées.

- `logs/`: Dossier d'archivage des événements individuels.

---
---
## 📜 Licence
Ce projet est sous licence **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.
Toute utilisation commerciale est strictement interdite sans autorisation préalable. Consultez le fichier [LICENSE](./LICENSE) pour plus de détails.

---
- **Auteur** : Alexis Rousseau - **Ingénieur | Administrateur Systeme Réseau et Cybersécurité**
- **Date** 22/04/2026
