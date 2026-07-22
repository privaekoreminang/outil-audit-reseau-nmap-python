# Outil d'audit et de reporting réseau (Python + Nmap)

Outil en ligne de commande développé en Python, réalisé dans le cadre de mon projet de soutenance DTS (INPTIC, Réseaux et Systèmes Numériques). Il automatise la découverte réseau, la détection de vulnérabilités et la génération de rapports professionnels.

## Contexte

Un audit réseau manuel (scan Nmap, lecture des résultats, rédaction du rapport) est répétitif et chronophage. Ce projet automatise l'ensemble de la chaîne : du scan à la sortie d'un rapport PDF prêt à être partagé, en passant par la conservation de l'historique en base de données.

## Fonctionnalités

- **Scan réseau** : découverte d'hôtes actifs sur un sous-réseau donné
- **Détection de services** : identification des ports ouverts, services, produits et versions (`-sV`)
- **Détection de vulnérabilités** : exécution de scripts NSE (`--script vuln`) pour repérer les failles connues
- **Persistance** : sauvegarde de chaque scan en base SQLite (historique consultable)
- **Reporting automatique** : génération d'un rapport PDF structuré (ReportLab) à chaque exécution

## Architecture du projet

```
├── main.py            # Point d'entrée : orchestre scan → DB → PDF
├── scripts_scan.py     # Validation des arguments + exécution du scan Nmap
├── scripts_db.py        # Gestion de la base SQLite (schéma, insertion)
└── scripts_pdf.py       # Génération du rapport PDF avec ReportLab
```

## Technologies utilisées

- **Python 3**
- **python-nmap** — interface Python vers le binaire Nmap
- **SQLite3** — persistance locale des résultats
- **ReportLab** — génération de rapports PDF

## Prérequis

- Nmap installé sur la machine (`apt install nmap` / `brew install nmap`)
- Python 3.8+

## Installation

```bash
git clone https://github.com/privaekoreminang/network-audit-tool-python.git
cd network-audit-tool-python
pip install -r requirements.txt
```

## Utilisation

```bash
python main.py -Ah 192.168.1.0/24 -p 1-1000
```

- `-Ah` / `--All-hosts` : sous-réseau ou hôte cible (ex: `192.168.1.0/24`)
- `-p` / `--port` : plage de ports à scanner (ex: `1-1000`)

À l'issue de l'exécution :
1. Les résultats s'affichent dans le terminal
2. Ils sont sauvegardés dans `script_scan.db`
3. Un rapport PDF horodaté est généré automatiquement dans le dossier courant

## Exemple de sortie terminal

```
-----------------------------------------------
Hôte: 192.168.1.10    État: up
  - Port 22/tcp: open - ssh (OpenSSH 8.2)
  - Port 80/tcp: open - http (Apache 2.4.41)
      [!] Résultats NSE :
         - http-vuln-cve2017-5638: NOT VULNERABLE ...
```

## Limites et pistes d'amélioration

- Le script NSE est actuellement fixé à `vuln` — pourrait être rendu configurable en argument CLI
- Pas de gestion de l'authentification pour des scans nécessitant des privilèges élevés
- Le rapport PDF pourrait intégrer des graphiques de synthèse (ports ouverts par service, criticité des vulnérabilités)

## Avertissement

⚠️ Cet outil doit être utilisé uniquement sur des réseaux dont vous avez l'autorisation explicite d'audit. Le scan non autorisé de systèmes tiers est illégal.

## Auteur

**Priva EKORE MINANG** — Étudiant en Réseaux & Cybersécurité, INPTIC (Libreville, Gabon)
[LinkedIn](https://www.linkedin.com/in/priva-ekore-minang-023107420?utm_source=share_via&utm_content=profile&utm_medium=member_android) · [GitHub](https://github.com/privaekoreminang)
