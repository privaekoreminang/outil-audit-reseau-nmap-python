"""
scripts_db.py
-------------
Gestion de la persistance des résultats de scan dans une base SQLite locale.

Schéma relationnel (4 tables en cascade) :
    scans (1) ---- (N) hosts (1) ---- (N) ports (1) ---- (N) scripts

- scans   : un enregistrement par exécution de scan (cible, ports, script NSE utilisé)
- hosts   : les hôtes détectés pour un scan donné
- ports   : les ports ouverts/détectés pour un hôte donné
- scripts : les résultats des scripts NSE (ex: vulnérabilités) pour un port donné

Le ON DELETE CASCADE garantit que la suppression d'un scan supprime
automatiquement tous les hosts/ports/scripts associés.
"""

import sqlite3
from typing import Dict, Any, Optional, Iterable


class DatabaseManager:
    """
    Encapsule toutes les opérations SQLite : création du schéma, insertion
    des résultats de scan, fermeture propre de la connexion.
    """

    def __init__(self, db_path: str = "script_scan.db"):
        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None

    def init_db(self) -> None:
        """
        Ouvre la connexion à la base et crée les 4 tables si elles
        n'existent pas encore (idempotent — sûr à appeler plusieurs fois).
        """
        self.conn = sqlite3.connect(self.db_path)
        cur = self.conn.cursor()
        # Nécessaire pour que les ON DELETE CASCADE fonctionnent réellement
        cur.execute("PRAGMA foreign_keys = ON;")

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                targets TEXT,
                ports TEXT,
                nse_script TEXT,
                created_at TEXT DEFAULT (DATETIME('now'))
            )
            """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                ip TEXT,
                state TEXT,
                hostname TEXT,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
            """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER,
                port INTEGER,
                proto TEXT,
                state TEXT,
                service TEXT,
                product TEXT,
                version TEXT,
                FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
            )
            """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS scripts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                port_id INTEGER,
                script_name TEXT,
                output TEXT,
                FOREIGN KEY(port_id) REFERENCES ports(id) ON DELETE CASCADE
            )
            """
        )

        self.conn.commit()

    def close(self) -> None:
        """Ferme proprement la connexion SQLite si elle est ouverte."""
        if self.conn:
            try:
                self.conn.close()
            finally:
                self.conn = None

    def _ensure_conn(self) -> None:
        """Ouvre la connexion à la demande si elle ne l'est pas déjà."""
        if self.conn is None:
            self.init_db()

    def insert_scan_summary(self, targets: str, ports: str, nse_script: str) -> int:
        """Insère un enregistrement 'scan' et retourne son id (scan_id)."""
        self._ensure_conn()
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO scans (targets, ports, nse_script) VALUES (?, ?, ?)",
            (targets, ports, nse_script),
        )
        self.conn.commit()
        return cur.lastrowid

    def insert_host(self, scan_id: int, ip: str, state: Optional[str], hostname: Optional[str]) -> int:
        """Insère un hôte rattaché à un scan et retourne son id (host_id)."""
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO hosts (scan_id, ip, state, hostname) VALUES (?, ?, ?, ?)",
            (scan_id, ip, state, hostname),
        )
        self.conn.commit()
        return cur.lastrowid

    def insert_port(
        self,
        host_id: int,
        port: int,
        proto: Optional[str],
        state: Optional[str],
        service: Optional[str],
        product: Optional[str],
        version: Optional[str],
    ) -> int:
        """Insère un port rattaché à un hôte et retourne son id (port_id)."""
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO ports (host_id, port, proto, state, service, product, version) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (host_id, port, proto, state, service, product, version),
        )
        self.conn.commit()
        return cur.lastrowid

    def insert_script(self, port_id: int, script_name: str, output: str) -> int:
        """Insère un résultat de script NSE rattaché à un port."""
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO scripts (port_id, script_name, output) VALUES (?, ?, ?)",
            (port_id, script_name, output),
        )
        self.conn.commit()
        return cur.lastrowid

    def save_results(self, results: Dict[str, Any], targets: str, ports: str, nse_script: str) -> int:
        """
        Point d'entrée principal : sauvegarde en base la structure de
        résultats produite par run_scan_and_parse() (voir scripts_scan.py).

        Parcourt le dict hôte par hôte, puis port par port, puis script par
        script, en insérant chaque niveau et en réutilisant l'id généré par
        le niveau parent (scan_id -> host_id -> port_id).

        Chaque insertion est protégée par un try/except : si une entrée est
        malformée (ex: port non convertible en int), elle est simplement
        ignorée plutôt que de faire échouer tout le scan.

        Retourne le scan_id, utilisé ensuite pour générer le rapport PDF
        correspondant à ce scan précis.
        """
        self._ensure_conn()
        scan_id = self.insert_scan_summary(targets, ports, nse_script)

        for host_ip, host_entry in (results or {}).items():
            # Compatibilité clés anglaises/françaises selon la source des données
            host_state = host_entry.get("state") or host_entry.get("Etat")
            host_name = host_entry.get("hostname") or host_entry.get("Nom")

            try:
                host_id = self.insert_host(scan_id, host_ip, host_state, host_name)
            except Exception:
                continue
            ports_dict = host_entry.get("ports") or host_entry.get("Ports") or {}
            for port_key, p in ports_dict.items():
                port_num = p.get("port")
                proto = p.get("proto") or p.get("Proto")
                pstate = p.get("state") or p.get("Etat")
                service = p.get("service") or p.get("Service")
                product = p.get("product") or p.get("Production")
                version = p.get("version") or p.get("Version")
                try:
                    port_int = int(port_num)
                except Exception:
                    continue

                try:
                    port_id = self.insert_port(host_id, port_int, proto, pstate, service, product, version)
                except Exception:
                    continue

                scripts = p.get("scripts") or p.get("Scripts") or {}
                if isinstance(scripts, dict):
                    for sname, sout in scripts.items():
                        try:
                            self.insert_script(port_id, str(sname), str(sout))
                        except Exception:
                            continue

        return scan_id
