"""
scripts_pdf.py
---------------
Génération d'un rapport PDF professionnel à partir des résultats de scan
stockés en base SQLite (voir scripts_db.py), via la bibliothèque ReportLab.

Structure du rapport généré :
1. Page de titre : métadonnées du scan (date, cible, ports, script NSE)
2. Détail par hôte : tableau des ports/services détectés + tableau des
   résultats de scripts NSE (vulnérabilités) le cas échéant
3. Conclusion
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)
from datetime import datetime
import sqlite3
import os


def generate_pdf(db_path: str, scan_id: int) -> str:
    """
    Génère un rapport PDF professionnel et dynamique à partir de la base SQLite.
    Les tableaux s'adaptent à la longueur du texte et les colonnes NSE sont reformattées.

    Arguments :
        db_path : chemin vers le fichier SQLite contenant les résultats
        scan_id : identifiant du scan à documenter (retourné par
                  DatabaseManager.save_results())

    Retourne le chemin absolu du fichier PDF généré.
    """

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    # --- Récupération des métadonnées du scan ---
    cur.execute(
        "SELECT id, targets, ports, nse_script, created_at FROM scans WHERE id = ?",
        (scan_id,),
    )
    scan = cur.fetchone()
    if not scan:
        raise ValueError(f"Aucun scan trouvé pour l'ID {scan_id}")

    scan_id, targets, ports, nse_script, created_at = scan

    # --- Création du fichier PDF (nommé avec un horodatage pour éviter les collisions) ---
    pdf_name = f"rapport_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf_path = os.path.join(os.getcwd(), pdf_name)
    doc = SimpleDocTemplate(
        pdf_path, pagesize=A4, rightMargin=2 * cm, leftMargin=2 * cm, topMargin=2 * cm
    )

    # --- Définition des styles de texte utilisés dans le document ---
    styles = getSampleStyleSheet()
    style_title = ParagraphStyle(
        "TitrePrincipal",
        fontSize=22,
        alignment=1,  # centré
        spaceAfter=25,
        textColor=colors.HexColor("#1A5276"),
        fontName="Helvetica-Bold",
    )
    style_subtitle = ParagraphStyle(
        "SousTitre",
        fontSize=14,
        textColor=colors.HexColor("#154360"),
        spaceAfter=12,
        fontName="Helvetica-Bold",
    )
    style_text = ParagraphStyle(
        "TexteNormal",
        fontSize=10.5,
        leading=15,
        spaceAfter=8,
    )

    style_table_text = ParagraphStyle(
        "TexteTableau",
        fontSize=9,
        leading=12,
        wordWrap="CJK",  # permet le retour à la ligne automatique dans les cellules
    )

    elements = []

    # --- Page de titre ---
    elements.append(Paragraph("Rapport d’audit réseau", style_title))
    elements.append(Spacer(1, 0.5 * cm))
    elements.append(Paragraph(f"<b>Date du scan :</b> {created_at}", style_text))
    elements.append(Paragraph(f"<b>Réseau scanné :</b> {targets}", style_text))
    elements.append(Paragraph(f"<b>Ports scannés :</b> {ports}", style_text))
    elements.append(Paragraph(f"<b>Script NSE utilisé :</b> {nse_script}", style_text))
    elements.append(Spacer(1, 0.8 * cm))
    elements.append(
        Paragraph(
            "Ce rapport présente les résultats détaillés du scan réseau réalisé automatiquement via Nmap et ses scripts NSE. "
            "Les informations ci-dessous mettent en évidence les hôtes identifiés, les services actifs et les vulnérabilités détectées.",
            style_text,
        )
    )
    elements.append(PageBreak())

    # --- Détails par hôte ---
    elements.append(Paragraph("Détails par hôte", style_subtitle))
    cur.execute("SELECT id, ip, state, hostname FROM hosts WHERE scan_id = ?", (scan_id,))
    hosts = cur.fetchall()

    if not hosts:
        elements.append(Paragraph("Aucun hôte détecté durant ce scan.", style_text))
    else:
        for host_id, ip, state, hostname in hosts:
            elements.append(Spacer(1, 0.4 * cm))
            elements.append(Paragraph(f"<b>Adresse IP :</b> {ip}", style_text))
            elements.append(Paragraph(f"<b>État :</b> {state or 'inconnu'}", style_text))
            elements.append(Paragraph(f"<b>Nom d’hôte :</b> {hostname or 'non résolu'}", style_text))
            elements.append(Spacer(1, 0.3 * cm))

            # --- Table des ports détectés pour cet hôte ---
            cur.execute(
                "SELECT id, port, proto, state, service, product, version FROM ports WHERE host_id = ?",
                (host_id,),
            )
            ports_data = cur.fetchall()
            if ports_data:
                data = [["Port", "Protocole", "État", "Service", "Produit", "Version"]]
                for port_id, port, proto, pstate, service, product, version in ports_data:
                    # Chaque cellule est un Paragraph (et non une simple string) pour
                    # permettre le retour à la ligne automatique sur les textes longs
                    data.append([
                        Paragraph(str(port), style_table_text),
                        Paragraph(proto or "-", style_table_text),
                        Paragraph(pstate or "-", style_table_text),
                        Paragraph(service or "-", style_table_text),
                        Paragraph(product or "-", style_table_text),
                        Paragraph(version or "-", style_table_text),
                    ])
                table = Table(data, colWidths=[2*cm, 2.2*cm, 2*cm, 3*cm, 3*cm, 3*cm])
                table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2E86C1")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]))
                elements.append(table)
                elements.append(Spacer(1, 0.5 * cm))

                # --- Table des résultats de scripts NSE (vulnérabilités) pour cet hôte ---
                cur.execute(
                    """
                    SELECT s.script_name, s.output
                    FROM scripts s
                    JOIN ports p ON s.port_id = p.id
                    WHERE p.host_id = ?
                    """,
                    (host_id,),
                )
                scripts_data = cur.fetchall()
                if scripts_data:
                    elements.append(Paragraph("<b>Vulnérabilités NSE détectées :</b>", style_text))
                    script_table = [["Script", "Résultat du script"]]
                    for sname, sout in scripts_data:
                        # Nettoyage : les sorties NSE contiennent souvent des retours
                        # à la ligne qui casseraient la mise en page du tableau
                        sout_clean = sout.strip().replace("\n", " ")
                        cell_text = Paragraph(sout_clean, style_table_text)
                        script_table.append([Paragraph(sname, style_table_text), cell_text])

                    table2 = Table(script_table, colWidths=[5 * cm, 10 * cm])
                    table2.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#CB4335")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]))
                    elements.append(table2)
                    elements.append(Spacer(1, 0.7 * cm))

            elements.append(Spacer(1, 0.6 * cm))

    # --- Conclusion ---
    elements.append(PageBreak())
    elements.append(Paragraph("Conclusion", style_subtitle))
    elements.append(
        Paragraph(
            "Les résultats présentés dans ce rapport proviennent d’un audit automatisé réalisé avec Nmap et ses scripts NSE. "
            "Ils permettent d’identifier les services actifs et d’évaluer d’éventuelles vulnérabilités sur le réseau scanné. "
            "Ce rapport doit être exploité uniquement à des fins de diagnostic et de sécurisation légitime des systèmes concernés.",
            style_text,
        )
    )

    doc.build(elements)
    conn.close()
    return pdf_path
