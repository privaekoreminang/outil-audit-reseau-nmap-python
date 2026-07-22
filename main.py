"""
main.py
-------
Point d'entrée de l'outil d'audit réseau.

Usage :
    python main.py -Ah 192.168.1.0/24 -p 1-1000

Enchaîne les 4 étapes du pipeline :
1. Parsing et validation des arguments CLI (réseau cible, plage de ports)
2. Scan Nmap + parsing des résultats (scripts_scan.py)
3. Sauvegarde des résultats en base SQLite (scripts_db.py)
4. Génération automatique du rapport PDF (scripts_pdf.py)
"""

import argparse
from scripts_db import DatabaseManager
from scripts_scan import validation_ports, validation_reseau, run_scan_and_parse, display_results
from scripts_pdf import generate_pdf


if __name__ == "__main__":
    # --- Définition des arguments en ligne de commande ---
    parser = argparse.ArgumentParser(description="Outil : scan nmap + détection de vulnérabilités via NSE")
    parser.add_argument("-Ah", "--All-hosts", dest="sous_reseau", type=validation_reseau, help="Sous-réseau à scanner (ex: 192.168.1.0/24)")
    parser.add_argument("-p", "--port", dest="ports", type=validation_ports, help="Port ou intervalle, ex: 22 ou 20-80")

    args = parser.parse_args()

    reseau = args.sous_reseau
    ports = args.ports
    # Script NSE fixé à "vuln" : recherche de vulnérabilités connues sur les
    # services détectés (peut être rendu configurable via un argument CLI
    # supplémentaire si besoin d'utiliser d'autres scripts NSE)
    nse_script = "vuln"

    # --- Étape 1 : scan + parsing ---
    results = run_scan_and_parse(reseau, ports, nse_script)
    display_results(results)

# --- Étape 2 : sauvegarde en base + génération du rapport PDF ---
# Bloc volontairement séparé du if __name__ ci-dessus pour isoler la gestion
# des erreurs de persistance (DB/PDF) de celle du scan lui-même.
try:
    db = DatabaseManager("script_scan.db")
    db.init_db()
    scan_id = db.save_results(results, reseau, ports, nse_script)
    print(f"[+] Résultats sauvegardés en base (script_scan.db), scan_id = {scan_id}")

    pdf_path = generate_pdf(db_path="script_scan.db", scan_id=scan_id)
    print(f"[+] Rapport PDF généré automatiquement : {pdf_path}")

except Exception as e:
    print(f"[!] Erreur lors de la sauvegarde ou de la génération PDF : {e}")
finally:
    try:
        db.close()
    except Exception:
        pass
