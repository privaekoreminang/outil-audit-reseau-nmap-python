"""
scripts_scan.py
----------------
Module responsable de :
1. La validation des arguments utilisateur (plage de ports, sous-réseau).
2. L'exécution du scan Nmap (découverte d'hôtes, ports, services, scripts NSE).
3. L'affichage lisible des résultats dans le terminal.

Dépendance principale : python-nmap (wrapper Python autour du binaire nmap).
"""

import nmap
import argparse
import ipaddress
from typing import Dict, Any, List, Optional
import re
from textwrap import shorten


def validation_ports(s: str) -> str:
    """
    Valide le format d'une plage de ports passée en argument CLI (-p).

    Format attendu : "start-end", ex: "20-80".
    Lève une ArgumentTypeError (comprise nativement par argparse) si le
    format est invalide, si les valeurs sont hors plage (1-65535), ou si
    start > end.

    Retourne la chaîne telle quelle si elle est valide (elle sera transmise
    directement à python-nmap, qui accepte ce format).
    """
    _argparse = argparse

    if s is None:
        raise _argparse.ArgumentTypeError("Vous devez fournir un intervalle de ports, ex: '1-80'.")

    s = str(s).strip()
    if s == "":
        raise _argparse.ArgumentTypeError("Intervalle vide — utilisez le format 'start-end', ex: '1-80'.")

    # Le format doit être strictement "chiffres-chiffres" (pas de virgules, d'espaces, etc.)
    if not re.fullmatch(r"\d{1,5}-\d{1,5}", s):
        raise _argparse.ArgumentTypeError("Format invalide : doit être 'start-end' (ex: '1-80'), pas de virgules ni d'espaces.")

    start_str, end_str = s.split("-", 1)
    try:
        start = int(start_str)
        end = int(end_str)
    except ValueError:
        raise _argparse.ArgumentTypeError(f"Intervalle invalide (entiers attendus) : '{s}'")

    # Les ports valides vont de 1 à 65535 (limite du protocole TCP/UDP)
    if not (1 <= start <= 65535) or not (1 <= end <= 65535):
        raise _argparse.ArgumentTypeError(f"Ports hors plage : les valeurs doivent être entre 1 et 65535 (reçu: {start}-{end}).")

    if start > end:
        raise _argparse.ArgumentTypeError(f"Intervalle mal formé : start ({start}) > end ({end}).")

    return s


def validation_reseau(net: Optional[str]):
    """
    Valide et normalise le sous-réseau/l'hôte cible passé en argument CLI (-Ah).

    Utilise le module ipaddress pour vérifier que la valeur est un réseau IP
    valide (ex: "192.168.1.0/24"). strict=False permet d'accepter une IP
    avec des bits d'hôte non nuls (ex: "192.168.1.5/24").

    Retourne la représentation normalisée du réseau sous forme de chaîne.
    """
    if net is None or str(net).strip() == "":
        raise argparse.ArgumentTypeError("le réseau ne doit pas etre vide ")
    try:
        return str(ipaddress.ip_network(net, strict=False))
    except ValueError:
        raise argparse.ArgumentTypeError(f"Réseau invalide : {net}")


def run_scan_and_parse(reseau: str, ports: str, nse_script: str = "vuln") -> Dict[str, Any]:
    """
    Lance le scan Nmap sur le réseau/les ports donnés et parse les résultats
    dans une structure de données Python simple (dict) facilement réutilisable
    par les autres modules (base de données, génération PDF, affichage).

    Arguments Nmap utilisés :
    - -sV : détection de version des services (service/product/version)
    - --script <nse_script> : exécution d'un script NSE (par défaut "vuln",
      qui recherche des vulnérabilités connues sur les services détectés)

    Retourne un dict de la forme :
    {
        "<ip_hote>": {
            "Etat": "up"/"down",
            "Nom": "<hostname ou None>",
            "Ports": {
                "<port>/<proto>": {
                    "port": int,
                    "proto": "tcp"/"udp",
                    "state": "open"/"closed"/...,
                    "service": str,
                    "product": str,
                    "version": str,
                    "scripts": { "<nom_script_nse>": "<sortie>" }
                },
                ...
            }
        },
        ...
    }
    """
    scanner = nmap.PortScanner()
    arguments = f"-sV --script {nse_script}"

    try:
        scanner.scan(hosts=reseau, ports=ports, arguments=arguments)
    except Exception as e:
        print(f"[ERREUR] Échec du scan : {e}")
        return {}

    results: Dict[str, Any] = {}

    for host in scanner.all_hosts():
        # état de l'hôte (up/down) — protégé par try/except car python-nmap
        # peut lever une exception si les données sont incomplètes
        try:
            etat_host = scanner[host].state()
        except Exception:
            etat_host = None

        try:
            nom_host = scanner[host].hostname()
        except Exception:
            nom_host = None

        entree_host: Dict[str, Any] = {
            'Etat': etat_host,
            'Nom': nom_host,
            'Ports': {}
        }

        # Parcourt tous les protocoles détectés (tcp, udp...) puis tous les
        # ports scannés pour chaque protocole
        for proto in scanner[host].all_protocols():
            ports_dict = scanner[host].get(proto, {})
            for port in sorted(ports_dict.keys()):
                port_info = ports_dict[port]
                port_entree = {
                    'port': int(port),
                    'proto': proto,
                    'state': port_info.get('state'),
                    'service': port_info.get('name'),
                    'product': port_info.get('product'),
                    'version': port_info.get('version'),
                    'scripts': {}
                }

                # Résultats des scripts NSE (ex: vulnérabilités détectées)
                # python-nmap retourne soit un dict {nom: sortie}, soit une
                # chaîne brute selon les cas — on gère les deux
                script_dict = port_info.get('script') or {}
                if isinstance(script_dict, dict):
                    for script_name, script_output in script_dict.items():
                        port_entree['scripts'][script_name] = str(script_output)
                else:
                    if script_dict:
                        port_entree['scripts']['raw'] = str(script_dict)

                entree_host['Ports'][f"{port}/{proto}"] = port_entree

        results[host] = entree_host
    return results


def get_host_value(h: dict, eng: str, fr: str, default=None):
    """
    Petit utilitaire de compatibilité : certaines structures de résultats
    utilisent des clés en anglais ('state', 'hostname') et d'autres en
    français ('Etat', 'Nom'). Cette fonction essaie la clé anglaise d'abord,
    puis la clé française en repli.
    """
    return h.get(eng) if eng in h else (h.get(fr, default))


def display_results(results: Dict[str, Any]):
    """
    Affiche les résultats du scan dans le terminal de façon lisible :
    pour chaque hôte, son état et son nom, puis pour chaque port ouvert,
    le service détecté et un résumé (tronqué) des résultats NSE.
    """
    for host_ip, host_entry in results.items():
        print("\n-----------------------------------------------")

        state = get_host_value(host_entry, 'state', 'Etat') or 'inconnu'
        hostname = get_host_value(host_entry, 'hostname', 'Nom')

        print(f"Hôte: {host_ip}    État: {state}")
        if hostname:
            print(f"  Nom : {hostname}")

        ports = get_host_value(host_entry, 'ports', 'Ports', {})
        if not ports:
            print("  (aucun port)")
            continue

        # Tri des ports par numéro pour un affichage ordonné
        for key, p in sorted(ports.items(), key=lambda kv: kv[1].get('port', 0)):
            port_num = p.get('port', 'inconnu')
            proto = p.get('proto', 'inconnu')
            pstate = p.get('state') or p.get('Etat') or 'inconnu'
            service = p.get('service') or p.get('Service') or 'inconnu'
            product = p.get('product') or p.get('Production') or ''
            version = p.get('version') or p.get('Version') or ''

            line = f"  - Port {port_num}/{proto}: {pstate} - {service}"
            if product or version:
                line += f" ({product} {version})".strip()
            print(line)

            # Résultats NSE : tronqués à 200 caractères pour ne pas noyer
            # le terminal (le détail complet reste disponible dans le PDF)
            scripts = p.get('scripts') or p.get('Scripts') or {}
            if scripts:
                print("      [!] Résultats NSE :")
                for sname, sout in scripts.items():
                    out_str = str(sout)
                    out_short = shorten(out_str, width=200, placeholder=" ...")
                    print(f"         - {sname}: {out_short}")
