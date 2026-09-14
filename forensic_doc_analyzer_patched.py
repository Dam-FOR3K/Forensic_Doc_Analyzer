import streamlit as st

def t(fr, en):
    if "lang" not in st.session_state:
        st.session_state["lang"] = "Français"
    return en if st.session_state["lang"] == "English" else fr

import functools

# Automatic UI translation layer for English selection
TRANSLATIONS_DICT = {
    "Analyse Horodatages des Flux (oletimes)": "Internal Stream Timestamps Analysis (oletimes)",
    "Injections DDE / DDEAUTO (msodde)": "DDE / DDEAUTO Injections (msodde)",
    "Extraction de Payloads OLE (oleobj / Quarantaine)": "OLE Payload Extraction (oleobj / Quarantine)",
    "Décompilation & Extraction de Code JavaScript (pdf-parser)": "JavaScript Code Decompilation & Extraction (pdf-parser)",
    "Fichiers Embarqués PDF (Quarantaine)": "PDF Embedded Files (Quarantine)",
    "Crédits & Bibliothèques Forensiques": "Credits & Forensic Libraries",
    "Indice de Suspicion & Risque Forensique": "Suspicion Index & Forensic Risk",
    "RISQUE ÉLEVÉ / CRITIQUE": "HIGH / CRITICAL RISK",
    "RISQUE MODÉRÉ": "MODERATE RISK",
    "RISQUE FAIBLE / NORMAL": "LOW / NORMAL RISK",
    "Aucune anomalie critique ou suspecte détectée sur ce document.": "No critical or suspicious anomaly detected in this document.",
    "indicateur(s) de risque identifié(s) :": "risk indicator(s) identified:",
    "📖 Glossaire & Explications des Alertes Forensiques": "📖 Glossary & Explanations of Forensic Alerts",
    "Signature(s) d'outils / convertisseurs détectée(s) :": "Converter/tool signature(s) detected:",
    "Aucune empreinte de convertisseur web gratuit connue détectée. Outil standard ou inconnu.": "No known free web converter fingerprint detected. Standard or unknown tool.",
    "Texte insuffisant pour réaliser une analyse stylométrique.": "Insufficient text to perform stylometric analysis.",
    "Note : Analyse stylométrique plafonnée aux": "Note: Stylometric analysis capped at",
    "Richesse lexicale très faible : répétitions importantes ou texte généré automatisé.": "Very low lexical richness: significant repetitions or automated/generated text.",
    "Richesse lexicale très élevée : vocabulaire dense et varié.": "Very high lexical richness: dense and varied vocabulary.",
    "Aucun horodatage collecté.": "No timestamps collected.",
    "Alerte Timestomping / Incohérence temporelle": "Timestomping Alert / Temporal inconsistency",
    "Chronologie cohérente. Aucune anomalie majeure de Timestomping détectée.": "Consistent timeline. No major Timestomping anomalies detected.",
    "signature(s) d'exploit / anomalie(s) YARA détectée(s) :": "exploit signature(s) / YARA anomaly(ies) detected:",
    "Aucune signature YARA ou d'exploit connue matchée.": "No known YARA signatures or exploits matched.",
    "URL(s) suspecte(s) ou liens à haut risque détectés :": "Suspicious URL(s) or high-risk links detected:",
    "URL(s) légitime(s) extraite(s) :": "Legitimate URL(s) extracted:",
    "Aucune URL extraite.": "No URLs extracted.",
    "objet(s) binaire(s) OLE / payload(s) embarqué(s) trouvé(s) !": "binary OLE object(s) / embedded payload(s) found!",
    "Aucun objet binaire OLE embarqué résiduel dans l'archive.": "No residual embedded binary OLE objects in the archive.",
    "ALERTE STÉGANOGRAPHIE": "STEGANOGRAPHY ALERT",
    "fichier(s) suspect(s) non-standard présent(s) dans le ZIP !": "suspicious non-standard file(s) present in the ZIP!",
    "Fichier dissimulé / non-standard :": "Hidden / non-standard file:",
    "Tous les composants de l'archive ZIP correspondent aux types et structures OOXML standards.": "All components of the ZIP archive match standard OOXML structures and types.",
    "fichier(s) de commentaires trouvé(s).": "comments file(s) found.",
    "Commentaires extraits de": "Comments extracted from",
    "POURQUOI C'EST UTILE :": "WHY IT IS USEFUL:",
    "Exports du rapport d'analyse": "Analysis Report Exports",
    "📥 Télécharger le rapport JSON (Données brutes / SIEM)": "📥 Download JSON report (Raw data / SIEM)",
    "⚖️ Télécharger le Rapport d'Analyse Forensique Horodaté (HTML/PDF Imprimable)": "📥 Download Timestamped Forensic Analysis Report (Printable HTML/PDF)",
    "Aperçu du rapport JSON": "JSON Report Preview",
    "Archive corrompue lors de la lecture de": "Corrupted archive when reading",
    "Erreur inattendue lors de la lecture de": "Unexpected error when reading",
    "Erreur inattendue lors de la lecture binaire de": "Unexpected error during binary read of",
    "Tous les fichiers XML internes sont a l'epoch ZIP 1980-01-01.": "All internal XML files are at the ZIP epoch 1980-01-01.",
    "Aucun texte exploitable trouve dans document.xml.": "No exploitable text found in document.xml.",
    "Aucun RSID exploitable au niveau des runs de texte.": "No exploitable RSID at the text runs level.",
    "Legende (session : nb de segments de texte) :": "Legend (session: number of text segments):",
    "Mode d'affichage du texte": "Text display mode",
    "Aucun paragraphe exploitable trouve dans document.xml.": "No exploitable paragraph found in document.xml.",
    "Tous les RSID de contenu utilises sont declares dans settings.xml.": "All content RSIDs used are declared in settings.xml.",
    "Aucun segment isole avec un RSID divergent detecte.": "No isolated segment with divergent RSID detected.",
    "Aucun paragraphe avec un rsidRPr distinct de son rsidR detecte.": "No paragraph with rsidRPr distinct from its rsidR detected.",
    "Aucun texte exploitable trouve pour l'analyse de langue.": "No exploitable text found for language analysis.",
    "Aucun rsidRoot trouve dans settings.xml.": "No rsidRoot found in settings.xml.",
    "Le rsidRoot declare apparait bien parmi les RSID observes dans le texte.": "The declared rsidRoot appears among the observed text runs.",
    "Aucun w15:docId trouve.": "No w15:docId found.",
    "Aucune protection de document active.": "No active document protection.",
    "Aucun texte marque comme cache (w:vanish).": "No text marked as hidden (w:vanish).",
    "Aucune anomalie évidente de masque (texte blanc, micro-police ou forme noire suspecte) détectée.": "No obvious mask anomalies (white text, micro-font, or suspicious black shape) detected.",
    "Aucun modèle attaché externe (attachedTemplate) détecté.": "No external attached template (attachedTemplate) detected.",
    "Sauvegarde récente uniforme": "Recent uniform save",
    "Les composants XML portent tous la date courante de sauvegarde": "The XML components all bear the current save date",
    "C'est le comportement standard d'un 'Enregistrer sous...' dans MS Word 2019/2021/365 sur Windows 11.": "This is the standard behavior of 'Save As...' in MS Word 2019/2021/365 on Windows 11.",
    "Fichier dissimulé / non-standard": "Hidden / non-standard file",
    "Tous les composants de l'archive ZIP correspondent aux types et structures OOXML standards": "All components of the ZIP archive match standard OOXML structures and types",
    "Faux Caviardage": "Fake Redaction",
    "Incohérence Auteur / Modificateur": "Author / Modifier inconsistency",
    "Modèle Distant (attachedTemplate UNC/Web)": "Remote Template (attachedTemplate UNC/Web)",
    "Timestomping Sous-Seconde (.000000)": "Sub-Second Timestomping (.000000)",
    "Payload OLE Embarqué": "Embedded OLE Payload",
    "Rapport d'Analyse Forensique Horodaté v1.0.0": "Timestamped Forensic Analysis Report v1.0.0",
    "Avertissement de Méthodologie Forensique": "Methodological Forensic Disclaimer",
    "Certificat d'Empreinte Numérique (Custody Proof)": "Digital Fingerprint Certificate (Custody Proof)",
    "Fichier analysé :": "Analyzed file:",
    "Empreinte SHA-256 :": "SHA-256 Fingerprint:",
    "Analyse de": "Analysis of",
    "Fichier source": "Source file",
    "Indicateur de Falsification": "Forgery Indicator",
    "Auteur Tiers / Anonymisé": "Third-party / Anonymized Author",
    "RSID Orphelin (Copier-Coller)": "Orphan RSID (Copy-Paste)",
    "Modèle distant (UNC/Web)": "Remote Template (UNC/Web)",
    "Timestomping Suspect": "Suspicious Timestomping",
    "Macro OLE / VBA": "OLE / VBA Macro",
    "Faux Caviardage (Texte masqué)": "Fake Redaction (Hidden text)",
    "Texte Camouflé (Blanc ou micro-police)": "Camouflaged Text (White or micro-font)",
    "Divergence Texte/HTML (Phishing)": "Text/HTML Divergence (Phishing)",
    "Analyse EML / MSG": "EML / MSG Analysis",
    "Grille de Méthodologie du Score Forensique": "Forensic Score Methodology Grid",
    "Échelle de Risque :": "Risk Scale:",
    "Risque Faible (Document Standard)": "Low Risk (Standard Document)",
    "Risque Modéré": "Moderate Risk",
    "Risque Élevé (Exploits / Payloads / Falsifications)": "High Risk (Exploits / Payloads / Forgeries)",
    "Chaque catégorie d'anomalie fait l'objet d'un plafonnement maximal pour éviter la saturation du score par des événements répétitifs mineurs.": "Each anomaly category has a maximum cap to prevent score saturation by minor repetitive events."
}

def translate_string(s):
    if not isinstance(s, str) or not s.strip():
        return s
    
    # Try direct lookup
    if s in TRANSLATIONS_DICT:
        return TRANSLATIONS_DICT[s]
    
    # Try dynamic pattern translation
    res = s
    res = re.sub(r'(\d+)\s+indicateur\(s\) de risque identifié\(s\)\s*:', r'\1 risk indicator(s) identified:', res)
    res = re.sub(r"(\d+)\s+signature\(s\) d'exploit\s+/\s+anomalie\(s\) YARA détectée\(s\)\s*:", r'\1 exploit signature(s) / YARA anomaly(ies) detected:', res)
    res = re.sub(r'(\d+)\s+URL\(s\) suspecte\(s\) ou liens à haut risque détectés\s*:', r'\1 suspicious URL(s) or high-risk links detected:', res)
    res = re.sub(r'(\d+)\s+URL\(s\) légitime\(s\) extraite\(s\)\s*:', r'\1 legitimate URL(s) extracted:', res)
    res = re.sub(r'(\d+)\s+objet\(s\) binaire\(s\) OLE / payload\(s\) embarqué\(s\) trouvé\(s\)\s*!', r'\1 binary OLE object(s) / embedded payload(s) found!', res)
    res = re.sub(r'Télécharger\s+(.*?)\s+\(Quarantaine\)', r'Download \1 (Quarantine)', res)
    res = re.sub(r'(\d+)\s+fichier\(s\) suspect\(s\) non-standard présent\(s\) dans le ZIP\s*!', r'\1 suspicious non-standard file(s) present in the ZIP!', res)
    res = re.sub(r'Fichier dissimulé / non-standard\s*:\s*`(.*?)`', r'Hidden / non-standard file: `\1`', res)
    res = re.sub(r'(\d+)\s+fichier\(s\) de commentaires trouvé\(s\)\.', r'\1 comments file(s) found.', res)
    res = re.sub(r'Commentaires extraits de\s*`(.*?)`\s*:', r'Comments extracted from `\1`:', res)
    res = re.sub(r'(\d+)\s+fichier\(s\) XML avec des timestamps ZIP hétérogènes\s*:', r'\1 XML file(s) with heterogeneous ZIP timestamps:', res)
    res = re.sub(r'(\d+)\s+RSID de contenu distinct\(s\) detecte\(s\),\s+dont\s+(\d+)\s+associe\(s\) directement a un paragraphe\.', r'\1 distinct content RSID(s) detected, including \2 directly associated with a paragraph.', res)
    res = re.sub(r'(\d+)\s+RSID présent\(s\) dans le texte mais absent\(s\) de la table déclarée\s*:\s*(.*)', r'\1 RSID present in text but absent from declared table: \2', res)
    res = re.sub(r'(\d+)\s+segment\(s\) isole\(s\) avec RSID different\s*:', r'\1 isolated segment(s) with different RSID:', res)
    res = re.sub(r'(\d+)\s+paragraphe\(s\) avec rsidRPr distinct\s*:', r'\1 paragraph(s) with distinct rsidRPr:', res)
    res = re.sub(r'Une seule langue detectee\s*:\s*(.*)', r'Only one language detected: \1', res)
    res = re.sub(r'(\d+)\s+langues distinctes detectees\s*:\s*(.*?)\.\s+(\d+)\s+transition\(s\) entre runs\.', r'\1 distinct languages detected: \2. \3 transition(s) between runs.', res)
    res = re.sub(r'Voir les\s+(\d+)\s+transition\(s\) de langue', r'See the \1 language transition(s)', res)
    res = re.sub(r'rsidRoot declare\s*:\s*(.*)', r'declared rsidRoot: \1', res)
    res = re.sub(r"Le rsidRoot\s+\((.*?)\)\s+n'apparait dans aucun run de texte observe\.", r'The rsidRoot (\1) does not appear in any observed text run.', res)
    res = re.sub(r'Protection active\s*:\s*mode\s*=\s*(.*?),\s+algo\s*=\s*(.*)', r'Active protection: mode = \1, algo = \2', res)
    res = re.sub(r'(\d+)\s+marqueur\(s\) de texte cache\s+\(w:vanish\)\s+detecte\(s\)\.', r'\1 hidden text marker(s) (w:vanish) detected.', res)
    res = re.sub(r'(\d+)\s+controle\(s\) de contenu structure\s+\(w:sdt\)\s+detecte\(s\)\.', r'\1 structured content control(s) (w:sdt) detected.', res)
    res = re.sub(r'(\d+)\s+anomalie\(s\) de masquage ou caviardage détectée\(s\)\s*:', r'\1 masking or redaction anomaly(ies) detected:', res)
    res = re.sub(r'ALERTE INJECTION / MODÈLE DISTANT\s+dans\s+`(.*?)`\s+->\s+`(.*?)`', r'INJECTION / REMOTE TEMPLATE ALERT in `\1` -> `\2`', res)
    res = re.sub(r'Modèle attaché dans\s+`(.*?)`\s+->\s+`(.*?)`', r'Attached template in `\1` -> `\2`', res)
    res = re.sub(r'(\d+)\s+feuille\(s\) cachée\(s\)\s*:', r'\1 hidden sheet(s):', res)
    res = re.sub(r'(\d+)\s+fichier\(s\) de révision trouvé\(s\)\.', r'\1 revision file(s) found.', res)
    res = re.sub(r'(\d+)\s+chaînes uniques \(sharedStrings\)', r'\1 unique strings (sharedStrings)', res)
    
    # Key phrases
    res = res.replace("Date création XLSX", "XLSX Creation Date")
    res = res.replace("Date modif XLSX", "XLSX Modification Date")
    res = res.replace("Métadonnées globales", "Global Metadata")
    res = res.replace("Dates & Horodatages", "Dates & Timestamps")
    res = res.replace("Indicateurs de Falsification", "Forgery Indicators")
    res = res.replace("Analyse ELA", "ELA Analysis")
    res = res.replace("Résumé de la Stylométrie", "Stylometry Summary")
    res = res.replace("Pièces Jointes", "Attachments")
    res = res.replace("En-têtes de Messagerie", "Email Headers")
    res = res.replace("Validation SPF / DKIM / DMARC", "SPF / DKIM / DMARC Validation")
    res = res.replace("Contenu Brut", "Raw Content")
    res = res.replace("Vue HTML", "HTML View")
    res = res.replace("Fichier", "File")
    res = res.replace("Valeur", "Value")
    res = res.replace("Emplacement de la preuve", "Evidence Location")
    res = res.replace("Indicateur", "Indicator")
    res = res.replace("Auteurs de révision", "Revision Authors")
    res = res.replace("Feuille", "Sheet")
    res = res.replace("Calculer", "Calculate")
    res = res.replace("Résultats de l'Analyse ELA", "ELA Analysis Results")
    res = res.replace("Tableau de bord de révision", "Revision Dashboard")
    res = res.replace("Indicateurs Forensic", "Forensic Indicators")
    res = res.replace("Date de l'événement", "Event Date")
    res = res.replace("Description de l'événement", "Event Description")
    res = res.replace("Source de l'événement", "Event Source")
    res = res.replace("Ligne du temps", "Timeline")
    res = res.replace("Événement", "Event")
    res = res.replace("Composant", "Component")
    res = res.replace("Aucune feuille cachée détectée.", "No hidden sheets detected.")
    res = res.replace("feuille(s) cachée(s) :", "hidden sheet(s):")
    res = res.replace("auteurs =", "authors =")
    
    return res

def wrap_translate(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if st.session_state.get("lang") == "English":
            new_args = []
            for arg in args:
                if isinstance(arg, str):
                    new_args.append(translate_string(arg))
                elif isinstance(arg, list):
                    new_args.append([translate_string(item) if isinstance(item, str) else item for item in arg])
                elif isinstance(arg, tuple):
                    new_args.append(tuple(translate_string(item) if isinstance(item, str) else item for item in arg))
                else:
                    new_args.append(arg)
            
            new_kwargs = {}
            for k, v in kwargs.items():
                if k in ['label', 'help', 'title', 'value'] and isinstance(v, str):
                    new_kwargs[k] = translate_string(v)
                elif isinstance(v, list):
                    new_kwargs[k] = [translate_string(item) if isinstance(item, str) else item for item in v]
                else:
                    new_kwargs[k] = v
            return func(*new_args, **new_kwargs)
        return func(*args, **kwargs)
    return wrapper

# Apply wrappers to Streamlit functions
st.write = wrap_translate(st.write)
st.markdown = wrap_translate(st.markdown)
st.success = wrap_translate(st.success)
st.warning = wrap_translate(st.warning)
st.error = wrap_translate(st.error)
st.info = wrap_translate(st.info)
st.subheader = wrap_translate(st.subheader)
st.title = wrap_translate(st.title)
st.caption = wrap_translate(st.caption)
st.text = wrap_translate(st.text)
st.radio = wrap_translate(st.radio)
st.selectbox = wrap_translate(st.selectbox)
st.checkbox = wrap_translate(st.checkbox)
st.button = wrap_translate(st.button)
st.download_button = wrap_translate(st.download_button)
st.metric = wrap_translate(st.metric)
st.expander = wrap_translate(st.expander)
st.tabs = wrap_translate(st.tabs)
import zipfile
import zlib
import re
import hashlib
import io
import subprocess
import tempfile
import os
import sys
import shutil
import base64
import struct
import inspect
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from pathlib import Path
from email import policy
from email.parser import BytesParser

# Résolution automatique du dossier tools/ local pour fonctionnement 100% hors-ligne (air-gapped)
def setup_local_tools_path():
    possible_dirs = []
    if getattr(sys, 'frozen', False):
        meipass = getattr(sys, '_MEIPASS', None)
        if meipass:
            possible_dirs.append(os.path.join(meipass, "tools"))
            possible_dirs.append(meipass)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    possible_dirs.append(os.path.join(base_dir, "tools"))
    possible_dirs.append(base_dir)
    
    for tdir in possible_dirs:
        if os.path.exists(tdir):
            if tdir not in sys.path:
                sys.path.insert(0, tdir)
            os.environ["PATH"] = tdir + os.path.pathsep + os.environ.get("PATH", "")

setup_local_tools_path()

# Imports optionnels PIL & YARA
YARA_AVAILABLE = False
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

PIL_AVAILABLE = False
try:
    from PIL import Image, ImageChops, ImageEnhance
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

st.set_page_config(page_title="Forensic Doc Analyzer v1.0.0", layout="wide")

st.title("🕵️ Forensic Doc Analyzer v1.0.0")
st.sidebar.markdown("### 🌍 Language / Langue")
st.session_state["lang"] = st.sidebar.radio("Language / Langue", ["Français", "English"], label_visibility="collapsed")

st.caption(t("Solution 100% locale & confidentielle — **Conçu par Dam-FOR3K (avec l'aide de l'IA Antigravity)** — v1.0.0", "100% local & confidential Solution — **Designed by Dam-FOR3K (with Antigravity AI)** — v1.0.0"))

st.sidebar.header(t("⚙️ Paramètres Forensiques", "⚙️ Forensic Settings"))

MAX_EXTRACT_BYTES = 1024 * 1024 * 1024  # 1 Go (1024 Mo) par fichier extrait
MAX_STYLOMETRY_CHARS = 1_000_000        # Max 1M caractères pour la stylométrie
MAX_ELA_IMAGE_BYTES = 50 * 1024 * 1024  # Max 50 Mo par image pour ELA

# Extensions exécutables et chaînes de payloads à haut risque
DANGEROUS_PAYLOAD_EXTS = {
    ".exe", ".dll", ".ps1", ".bat", ".cmd", ".hta", ".js", ".jse", ".wsf",
    ".wsh", ".jar", ".msi", ".vbe", ".cpl", ".iso", ".img", ".chm", ".scr",
    ".lnk", ".pif", ".bas", ".com", ".vbs"
}

# ----------------------------------------------------------------------------
# 1. Forensic Risk Engine (Score & Plafonnement par Catégorie)
# ----------------------------------------------------------------------------

# Plafonds maximaux de points accumulables par catégorie pour éviter la saturation artificielle
CATEGORY_MAX_CAPS = {
    "Injection DDE / DDEAUTO": 30,
    "Contournement PDFiD (Name Mangling)": 20,
    "Payload OLE Native (Ole10Native)": 25,
    "Macros Excel 4.0 (XLM)": 25,
    "RSID Orphelin": 20,
    "Auteur / Révision Tiers": 10,
    "Stéganographie ZIP": 30,
    "Convertisseur Web": 15,
    "PDF Incrémental": 15,
    "Masquage Texte": 25,
    "Texte Camouflé": 30,
    "Micro-police": 15,
    "Faux Caviardage": 35,
}

class ForensicRiskEngine:
    def __init__(self):
        self.findings = []
        self.score = 0
        self.category_totals = {}

    def add_risk(self, points: int, severity: str, category: str, description: str, source_location: str = None):
        # Dédoublonnage sur description exacte
        for existing in self.findings:
            if existing["category"] == category and existing["description"] == description:
                return
        
        # Plafonnement par catégorie
        current_cat_total = self.category_totals.get(category, 0)
        max_cap = CATEGORY_MAX_CAPS.get(category, 100)
        
        if current_cat_total >= max_cap:
            effective_points = 0
        else:
            effective_points = min(points, max_cap - current_cat_total)
            self.category_totals[category] = current_cat_total + effective_points

        self.score = min(100, self.score + effective_points)
        self.findings.append({
            "points": effective_points,
            "raw_points": points,
            "severity": severity,  # 'CRITIQUE', 'HAUT', 'MOYEN', 'FAIBLE'
            "category": category,
            "description": description,
            "source_location": source_location or "N/A"
        })

    def render_risk_badge(self):
        st.subheader("Indice de Suspicion & Risque Forensique")
        col1, col2 = st.columns([1, 3])
        with col1:
            if self.score >= 60:
                st.error(f"## 🚨 {self.score} / 100\n**RISQUE ÉLEVÉ / CRITIQUE**")
            elif self.score >= 25:
                st.warning(f"## ⚠️ {self.score} / 100\n**RISQUE MODÉRÉ**")
            else:
                st.success(f"## ✅ {self.score} / 100\n**RISQUE FAIBLE / NORMAL**")

        with col2:
            if not self.findings:
                st.write("Aucune anomalie critique ou suspecte détectée sur ce document.")
            else:
                st.write(f"**{len(self.findings)} indicateur(s) de risque identifié(s) :**")
                for f in self.findings:
                    badge_color = "red" if f["severity"] in (t("CRITIQUE", "CRITICAL"), "HAUT") else ("orange" if f["severity"] == "MOYEN" else "blue")
                    pts_label = f"+{f['points']} pts" if f['points'] > 0 else "0 pt (Plafond atteint)"
                    src_str = f" • 📍 *Source : `{f['source_location']}`*" if f.get('source_location') and f['source_location'] != "N/A" else ""
                    st.markdown(f":{badge_color}[**[{f['severity']}]** ({f['category']})] {f['description']} *({pts_label})*{src_str}")

        render_alert_glossary()



def render_alert_glossary():
    with st.expander("📖 Glossaire & Explications des Alertes Forensiques", expanded=False):
        st.markdown(r"""
        * **RSID Orphelin (non déclaré dans settings.xml)** : Un RSID (*Revision Save ID*) est un identifiant de session de sauvegarde généré par Word. Lorsqu'un RSID présent dans le texte n'est **PAS** répertorié dans la table `settings.xml`, cela indique que ce fragment de texte a été **copié-collé depuis un autre document Word externe** ou injecté par script.
        * **Modèle Distant (attachedTemplate UNC/Web)** : Le document tente de charger un modèle Word depuis un serveur web ou un partage réseau UNC (`\\\\serveur\\partage`). Souvent utilisé dans les attaques par injection de modèle pour exécuter du code à l'ouverture.
        * **Timestomping Sous-Seconde (.000000)** : Les sauvegardes réelles génèrent des microsecondes aléatoires (`.184920`). Une fraction de seconde égale à pile `.000000` est la signature d'une modification manuelle de la date via un outil d'anti-forensics ou un script.
        * **Payload OLE Embarqué** : Présence de fichiers exécutables ou de scripts (`.exe`, `.ps1`, `.bat`, `.vbs`, etc.) dissimulés à l'intérieur du document.
        * **Faux Caviardage** : Des bandes noires géométriques ont été dessinées par-dessus le texte pour le masquer visuellement, mais le texte d'origine est toujours présent en clair dans le code XML sous-jacent.
        * **Incohérence Auteur / Modificateur** : Le créateur d'origine (`dc:creator`) et le dernier modificateur (`cp:lastModifiedBy`) sont deux personnes différentes.
        """)

    with st.expander("📜 Crédits & Bibliothèques Forensiques (Open Source)", expanded=False):
        st.markdown("""
        * **Didier Stevens :** PDF Tools (`pdfid`, `pdf-parser`) — [blog.didierstevens.com](https://blog.didierstevens.com)
        * **Philippe Lagadec (decalage2) :** `oletools` (`olevba`, `oleid`, `oletimes`, `oleobj`, `msodde`) — [decalage.info](https://www.decalage.info)
        * **Phil Harvey :** `ExifTool` — [exiftool.org](https://exiftool.org)
        * **Matthias Valcke :** `PyHanko` — [github.com/MatthiasValcke/pyHanko](https://github.com/MatthiasValcke/pyHanko)
        * **Dam-FOR3K (avec l'aide de l'IA Antigravity) :** Conception & Interface
        """)



# ----------------------------------------------------------------------------
# 2. Image ELA Engine (Error Level Analysis - Diagnostic robuste)
# ----------------------------------------------------------------------------

def compute_ela_image(image_bytes: bytes, quality: int = 95) -> tuple[bytes | None, str]:
    """Génère la carte ELA et retourne (ela_bytes, status_message)."""
    if not PIL_AVAILABLE:
        return None, "Module Pillow non disponible."
    if not image_bytes:
        return None, "Données d'image vides."
    if len(image_bytes) > MAX_ELA_IMAGE_BYTES:
        return None, f"Image trop volumineuse ({len(image_bytes)/(1024*1024):.1f} Mo > max 10 Mo)."
    try:
        orig = Image.open(io.BytesIO(image_bytes))
        img_format = orig.format or "Inconnu"
        
        # Convertir en RGB si la palette, RGBA ou CMYK l'exige
        if orig.mode not in ("RGB", "L"):
            orig = orig.convert("RGB")
        elif orig.mode == "L":
            orig = orig.convert("RGB")

        buffer = io.BytesIO()
        orig.save(buffer, "JPEG", quality=quality)
        buffer.seek(0)
        resaved = Image.open(buffer)
        
        ela_img = ImageChops.difference(orig, resaved)
        extrema = ela_img.getextrema()
        max_diff = max([ex[1] for ex in extrema]) or 1
        scale_factor = 255.0 / max_diff
        ela_img = ImageEnhance.Brightness(ela_img).enhance(scale_factor)
        
        out_buffer = io.BytesIO()
        ela_img.save(out_buffer, format="PNG")
        status = f"Carte ELA générée (format source : {img_format})"
        return out_buffer.getvalue(), status
    except Exception as e:
        return None, f"Erreur ELA ({type(e).__name__}: {e})"


# ----------------------------------------------------------------------------
# 3. Converter Profiling Engine
# ----------------------------------------------------------------------------

KNOWN_CONVERTERS_PATTERNS = [
    {"name": "Smallpdf (Service de conversion web)", "key": "smallpdf", "pattern": r"\bsmallpdf\b"},
    {"name": "ILovePDF (Service de conversion web)", "key": "ilovepdf", "pattern": r"\bilovepdf\b"},
    {"name": "PDF2Go (Convertisseur en ligne)", "key": "pdf2go", "pattern": r"\bpdf2go\b"},
    {"name": "Canva (Éditeur graphique)", "key": "canva", "pattern": r"\bcanva\b"},
    {"name": "LibreOffice Suite", "key": "libreoffice", "pattern": r"\blibreoffice\b|\bopenoffice\b"},
    {"name": "WPS Office Suite", "key": "wps", "pattern": r"\bwps\s*office\b|\bwps\s*writer\b"},
    {"name": "Google Docs / Drive Exporter", "key": "google", "pattern": r"\bgoogle\s*docs\b|\bdocs\.google\.com\b|\bgoogle\s*drive\b"},
    {"name": "Apple Pages", "key": "apple_pages", "pattern": r"\bapple\s*pages\b|\biwork\s*pages\b|\bcom\.apple\.pages\b|<application>pages</application>"},
    {"name": "Adobe Acrobat Pro", "key": "acrobat", "pattern": r"\badobe\s*acrobat\b|\bacrobat\s*pro\b"},
    {"name": "Ghostscript PDF Generator", "key": "ghostscript", "pattern": r"\bghostscript\b"},
]

def profile_document_converters(raw_bytes: bytes, metadata_str: str = "", risk_engine: ForensicRiskEngine = None) -> list:
    section("Profilage d'Outils & Provenance de Conversion", "Identifie la chaîne de logiciels et services en ligne utilisés pour produire ou modifier le document.")
    matches = []
    matches_details = []
    combined_str = (raw_bytes[:2000000].decode("latin1", errors="ignore") + " " + metadata_str).lower()
    
    for item in KNOWN_CONVERTERS_PATTERNS:
        match_obj = re.search(item["pattern"], combined_str, re.IGNORECASE)
        if match_obj:
            start = max(0, match_obj.start() - 15)
            end = min(len(combined_str), match_obj.end() + 15)
            context_snippet = combined_str[start:end].replace("\n", " ").strip()
            
            matches.append(item["name"])
            matches_details.append(f"**{item['name']}** *(📍 Extrait source : `{context_snippet}`)*")
            
            if item["key"] in ("smallpdf", "ilovepdf", "pdf2go"):
                if risk_engine:
                    risk_engine.add_risk(
                        15, "MOYEN", "Convertisseur Web",
                        f"Conversion via service web tiers : {item['name']}",
                        source_location=f"Empreinte binaire -> '{context_snippet}'"
                    )

    if matches_details:
        st.warning("Signature(s) d'outils / convertisseurs détectée(s) :")
        for detail in matches_details:
            st.markdown(f"• {detail}")
    else:
        st.info("Aucune empreinte de convertisseur web gratuit connue détectée. Outil standard ou inconnu.")
        
    return matches


# ----------------------------------------------------------------------------
# 4. Stylometry Engine (Plafonné à 500k caractères)
# ----------------------------------------------------------------------------

def analyze_stylometry(text_content: str) -> dict:
    section("Stylométrie Forensique & Analyse de Style", "Analyse la richesse lexicale et repère les ruptures de style.")
    if not text_content or len(text_content.strip()) < 100:
        st.caption("Texte insuffisant pour réaliser une analyse stylométrique.")
        return {}

    truncated_text = text_content[:MAX_STYLOMETRY_CHARS]
    if len(text_content) > MAX_STYLOMETRY_CHARS:
        st.caption(f"Note : Analyse stylométrique plafonnée aux {MAX_STYLOMETRY_CHARS} premiers caractères.")

    words = re.findall(r"\b\w+\b", truncated_text.lower())
    total_words = len(words)
    unique_words = len(set(words))
    ttr = (unique_words / total_words * 100) if total_words > 0 else 0
    
    # Découper par ponctuation (.!?), sauts de ligne (\n, \r) et séparateurs de paragraphe
    raw_sentences = [s.strip() for s in re.split(r"(?:[.!?]+\s+|\n+|\r+)", truncated_text) if s.strip()]
    sentence_word_counts = [len(re.findall(r"\b\w+\b", s)) for s in raw_sentences if len(re.findall(r"\b\w+\b", s)) > 0]
    
    total_sentences = len(sentence_word_counts)
    avg_sentence_len = (sum(sentence_word_counts) / total_sentences) if total_sentences > 0 else 0

    c1, c2, c3 = st.columns(3)
    c1.metric("Mots totaux (échantillon)", total_words)
    c2.metric("Richesse lexicale (TTR)", f"{ttr:.1f} %")
    c3.metric("Longueur moyenne des phrases", f"{avg_sentence_len:.1f} mots")

    if ttr < 25 and total_words > 300:
        st.warning("Richesse lexicale très faible : répétitions importantes ou texte généré automatisé.")
    elif ttr > 75 and total_words > 300:
        st.info("Richesse lexicale très élevée : vocabulaire dense et varié.")

    return {"total_words": total_words, "ttr": ttr, "avg_sentence_len": avg_sentence_len, "total_sentences": total_sentences}


# ----------------------------------------------------------------------------
# 5. Legal Grade Report Generator (Rigueur & Clause de Réserve)
# ----------------------------------------------------------------------------

def generate_legal_grade_report_html(filename: str, file_hash: str, risk_engine: ForensicRiskEngine, timeline: ForensicTimelineEngine, collector: ReportCollector) -> str:
    now_utc = datetime.now(timezone.utc).strftime("%d/%m/%Y à %H:%M:%S UTC")
    findings_data = collector.data.get("findings", {})
    
    creator = "Non spécifié"
    modifier = "Non spécifié"
    company = "Non spécifiée"
    revision = "Non spécifiée"
    total_time = "Non spécifié"
    doc_id = "Non spécifié"
    tools = []

    if "metadata_summary" in findings_data:
        m = findings_data["metadata_summary"]
        creator = m.get("creator", creator)
        modifier = m.get("last_modified_by", modifier)
        company = m.get("company", company)
        revision = m.get("revision", revision)
        total_time = m.get("total_edit_time", total_time)
        doc_id = m.get("doc_id", doc_id)
        tools = m.get("tools_detected", [])

    if "doc_id" in findings_data and findings_data["doc_id"]:
        doc_id = findings_data["doc_id"]

    findings_html = ""
    for f in risk_engine.findings:
        color = "#d9534f" if f["severity"] in (t("CRITIQUE", "CRITICAL"), "HAUT") else ("#f0ad4e" if f["severity"] == "MOYEN" else "#0275d8")
        pts_str = f"+{f['points']} pts" if f['points'] > 0 else "0 pt (Plafond)"
        src_tag = f"<br/><small style='color:#666;'>📍 Emplacement Source : <code>{f.get('source_location', 'N/A')}</code></small>" if f.get('source_location') and f['source_location'] != "N/A" else ""
        findings_html += f"<tr><td style='color:{color};font-weight:bold;'>[{f['severity']}]</td><td>{f['category']}</td><td>{f['description']}{src_tag}</td><td style='text-align:right;'>{pts_str}</td></tr>"
        
    timeline_html = ""
    for e in sorted(timeline.events, key=lambda x: x["timestamp"]):
        timeline_html += f"<tr><td>{e['timestamp']}</td><td>{e['source']}</td><td>{e['type']}</td><td>{e['description']}</td></tr>"

    author_mismatch_warning = ""
    if is_valid_person_name(creator) and is_valid_person_name(modifier) and creator != modifier:
        author_mismatch_warning = f"<p style='color:#d9534f;font-weight:bold;'>⚠️ Incohérence des identités : Le document a été créé par <u>{creator}</u> mais modifié en dernier par <u>{modifier}</u>.</p>"

    tools_str = ", ".join(tools) if tools else "Aucun convertisseur tiers détecté (Outil standard)"

    html = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <title>Rapport d'Analyse Forensique - {filename}</title>
        <style>
            @media print {{ @page {{ margin: 1.5cm; }} body {{ font-size: 10pt; }} }}
            body {{ font-family: 'Helvetica Neue', Arial, sans-serif; line-height: 1.5; color: #222; margin: 30px; background-color: #fff; }}
            .header-banner {{ border-bottom: 3px solid #1b365d; padding-bottom: 12px; margin-bottom: 20px; }}
            .header-banner h1 {{ color: #1b365d; margin: 0; font-size: 18pt; text-transform: uppercase; }}
            .header-banner p {{ color: #666; margin: 4px 0 0 0; font-size: 9pt; }}
            .box {{ background: #f8f9fa; border: 1px solid #e9ecef; border-left: 4px solid #1b365d; padding: 12px 15px; margin-bottom: 20px; border-radius: 4px; }}
            .disclaimer-box {{ background: #fff8f8; border: 1px solid #f5c6cb; border-left: 4px solid #d9534f; padding: 12px 15px; margin-bottom: 20px; border-radius: 4px; font-size: 9pt; }}
            .score-badge {{ display: inline-block; padding: 6px 14px; font-weight: bold; font-size: 13pt; border-radius: 4px; color: #fff; background-color: {'#d9534f' if risk_engine.score >= 60 else ('#f0ad4e' if risk_engine.score >= 25 else '#5cb85c')}; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 10px; margin-bottom: 20px; }}
            th, td {{ border: 1px solid #dee2e6; padding: 7px 10px; font-size: 9pt; text-align: left; }}
            th {{ background-color: #1b365d; color: #fff; font-weight: 600; }}
            tr:nth-child(even) {{ background-color: #f8f9fa; }}
            .footer {{ margin-top: 40px; border-top: 1px solid #ccc; padding-top: 10px; font-size: 8.5pt; color: #777; text-align: center; }}
        </style>
    </head>
    <body>
        <div class="header-banner">
            <h1>Rapport d'Analyse Forensique Horodaté v1.0.0</h1>
            <p>Conçu & Signé par Dam-FOR3K (avec l'aide de l'IA Antigravity) • Attestation d'Empreinte Numérique (SHA-256)</p>
        </div>

        <div class="disclaimer-box">
            <h4 style="margin-top:0;color:#d9534f;">⚠️ Avertissement de Méthodologie Forensique</h4>
            <p style="margin-bottom:0;">
                <strong>IMPORTANT :</strong> Ce logiciel est un assistant expérimental d'exploration et de tri. Aucun résultat automatisé ne doit être accepté comme preuve définitive sans corroboration manuelle. L'analyste doit vérifier de manière indépendante tous les événements, horodatages et anomalies en inspectant directement les structures de fichiers primaires à l'aide d'outils de référence indépendants.
            </p>
        </div>

        <div class="box">
            <h3 style="margin-top:0;color:#1b365d;">Certificat d'Empreinte Numérique (Custody Proof)</h3>
            <p><strong>Fichier analysé :</strong> {filename}</p>
            <p><strong>Empreinte SHA-256 :</strong> <code>{file_hash}</code></p>
            <p><strong>Date & Heure de l'analyse (UTC) :</strong> {now_utc}</p>
            <p><strong>Niveau de Suspicion :</strong> <span class="score-badge">Indice de Risque : {risk_engine.score} / 100</span></p>
        </div>

        <h2>1. Identité des Auteurs & Métadonnées d'Origine</h2>
        <div class="box" style="border-left-color: #0275d8;">
            <table style="margin:0;">
                <tr><td style="width:30%;"><strong>Auteur / Créateur (`dc:creator`) :</strong></td><td><strong>{creator}</strong></td></tr>
                <tr><td><strong>Dernier Modificateur (`cp:lastModifiedBy`) :</strong></td><td><strong>{modifier}</strong></td></tr>
                <tr><td><strong>Société / Organisation (`Company`) :</strong></td><td>{company}</td></tr>
                <tr><td><strong>Compteur de Révisions (`cp:revision`) :</strong></td><td>{revision}</td></tr>
                <tr><td><strong>Temps Total d'Édition Déclaré :</strong></td><td>{total_time}</td></tr>
                <tr><td><strong>Identifiant Unique (`w15:docId`) :</strong></td><td><code>{doc_id}</code></td></tr>
                <tr><td><strong>Outils & Convertisseurs Détectés :</strong></td><td>{tools_str}</td></tr>
            </table>
            {author_mismatch_warning}
        </div>

        <h2>2. Grille des Alertes & Anomalies Forensiques</h2>
        <table>
            <thead><tr><th>Sévérité</th><th>Catégorie</th><th>Description détaillée de l'anomalie</th><th style="text-align:right;">Pénalité</th></tr></thead>
            <tbody>{findings_html or "<tr><td colspan='4' style='text-align:center;'>✅ Aucune anomalie critique ou suspecte détectée sur ce document.</td></tr>"}</tbody>
        </table>

        <h2>3. Ligne du Temps Forensique Unifiée (Timeline)</h2>
        <table>
            <thead><tr><th>Horodatage</th><th>Source</th><th>Type d'événement</th><th>Description</th></tr></thead>
            <tbody>{timeline_html or "<tr><td colspan='4' style='text-align:center;'>Aucun horodatage collecté.</td></tr>"}</tbody>
        </table>

        <h2>4. Grille de Méthodologie du Score Forensique</h2>
        <div class="box" style="border-left-color: #6c757d;">
            <p><strong>Échelle de Risque :</strong> <code>0 - 24</code> : Risque Faible (Document Standard) | <code>25 - 59</code> : Risque Modéré | <code>60 - 100</code> : Risque Élevé (Exploits / Payloads / Falsifications)</p>
            <p style="font-size:8.5pt;color:#666;margin-bottom:0;">Chaque catégorie d'anomalie fait l'objet d'un plafonnement maximal pour éviter la saturation du score par des événements répétitifs mineurs.</p>
        </div>

        <div class="footer">
            Généré par Forensic Doc Analyzer v1.0.0 • <strong>Conçu & Signé par Dam-FOR3K (avec l'aide de l'IA Antigravity)</strong> • SHA-256 Rapport : {sha256_of(html_escape_local(filename).encode())}
        </div>
    </body>
    </html>
    """
    return html


# ----------------------------------------------------------------------------
# 6. Forensic Timeline Engine (Timestomping & Dates Futures)
# ----------------------------------------------------------------------------

class ForensicTimelineEngine:
    def __init__(self):
        self.events = []

    def add_event(self, timestamp: str | datetime, source: str, event_type: str, description: str):
        if not timestamp:
            return
        ts_str = str(timestamp).strip()
        m = re.match(r"^(\d{4}):(\d{2}):(\d{2})", ts_str)
        if m:
            ts_str = f"{m.group(1)}-{m.group(2)}-{m.group(3)}" + ts_str[10:]
            
        self.events.append({
            "timestamp": ts_str,
            "source": source,
            "type": event_type,
            "description": description
        })

    def render_timeline(self, collector: "ReportCollector" = None, risk_engine: ForensicRiskEngine = None):
        section("Ligne du Temps Forensique Unifiée (Timeline)", "Consolide les horodatages système, XML, EXIF et révisions pour détecter le Timestomping.")
        if not self.events:
            st.caption("Aucun horodatage collecté.")
            return

        sorted_events = sorted(self.events, key=lambda x: x["timestamp"])
        now_date = datetime.now(timezone.utc)
        
        anomalies = []
        parsed_dates = []
        for e in sorted_events:
            try:
                dt_part = e["timestamp"].split("T")[0] if "T" in e["timestamp"] else e["timestamp"][:10]
                dt = datetime.strptime(dt_part[:10], "%Y-%m-%d")
                if dt.year > 1980: # Ignorer l'époque 1980 ZIP standard
                    parsed_dates.append((dt, e))
                    
                    # Détection de Date Future Aberrante
                    if dt > now_date.replace(tzinfo=None) + timedelta(days=2):
                        anomalies.append(f"Horodatage futur aberrant ({dt.strftime('%Y-%m-%d')}) dans `{e['source']}` ({e['type']}).")
                        if risk_engine:
                            risk_engine.add_risk(25, "HAUT", "Timestomping Date Future", f"Horodatage futur ({dt.strftime('%Y-%m-%d')}) dans {e['source']}")
                            
                    # Détection de Timestomping Manuel Sub-Seconde (.000000 / 000ms)
                    if re.search(r"\.(?:000000|000|0000000)(?:Z|\+|-|$)", e["timestamp"]):
                        anomalies.append(f"Horodatage sous-seconde artificiellement nul (`.000000`) dans `{e['source']}` ({e['type']}).")
                        if risk_engine:
                            risk_engine.add_risk(15, "MOYEN", "Timestomping Sous-Seconde", f"Fraction de seconde nulle (.000000) dans {e['source']} ({e['type']})")
            except Exception:
                pass

        if len(parsed_dates) >= 2:
            first_dt, first_e = parsed_dates[0]
            last_dt, last_e = parsed_dates[-1]
            if (last_dt - first_dt).days > 3650:
                anomalies.append(f"Écart temporel extrême ({first_dt.strftime('%Y-%m-%d')} vs {last_dt.strftime('%Y-%m-%d')}) entre `{first_e['source']}` et `{last_e['source']}`.")
                if risk_engine:
                    risk_engine.add_risk(15, "MOYEN", "Timestomping Écart Extrême", f"Écart de {(last_dt - first_dt).days // 365} ans dans la chronologie")

        if anomalies:
            for a in anomalies:
                st.warning(f"**Alerte Timestomping / Incohérence temporelle** : {a}")
        else:
            st.success("Chronologie cohérente. Aucune anomalie majeure de Timestomping détectée.")

        table_rows = [["Horodatage (UTC/Déclaré)", "Source", "Type d'événement", t("Description", "Description")]]
        for e in sorted_events:
            table_rows.append([e["timestamp"], e["source"], e["type"], e["description"]])
        st.table(table_rows)

        if collector is not None:
            collector.add("unified_timeline", sorted_events)


# ----------------------------------------------------------------------------
# 7. YARA Scanner Engine (Borne ReDoS Sécurisée)
# ----------------------------------------------------------------------------

BUILTIN_REGEX_RULES = [
    {"name": "VBA_Macro_Obfuscation", "pattern": r"(?:AutoOpen|Workbook_Open|ShellExecute|WScript\.Shell|VirtualAlloc|WriteProcessMemory)", "risk": 30, "severity": "HAUT", "desc": "Présence de fonctions d'exécution/d'obfuscation VBA à risque."},
    {"name": "Office_Exploit_Follina", "pattern": r"(?:ms-msdt:|search-ms:|IT_ReFileType)", "risk": 40, "severity": t("CRITIQUE", "CRITICAL"), "desc": "Protocole Follina / ms-msdt suspect détecté dans les liens."},
    {"name": "Office_CVE_2021_40444", "pattern": r"(?:mhtml:http|htmlfile|ActiveXObject)", "risk": 35, "severity": t("CRITIQUE", "CRITICAL"), "desc": "Marqueurs d'exploitation ActiveX / MHTML (CVE-2021-40444)."},
    {"name": "Executable_Magic_Bytes", "pattern": r"TVqQAAMAAAAEAAAA", "risk": 35, "severity": "HAUT", "desc": "En-tête exécutable PE/Windows (MZ) encodé en Base64 masqué dans le document."},
    {"name": "PowerShell_Command_Injection", "pattern": r"(?:powershell\.exe|encodedcommand|-enc\s+[A-Za-z0-9+/=]{20,200})", "risk": 30, "severity": "HAUT", "desc": "Commande PowerShell obfusquée détectée."},
]

def run_yara_scan(raw_bytes: bytes, risk_engine: ForensicRiskEngine) -> list:
    section("Analyse YARA & Signatures IOC", "Recherche de signatures d'exploits et de macros obfusquées.")
    matches = []
    
    if YARA_AVAILABLE:
        rule_str = """
        rule Office_VBA_Suspicious {
            strings:
                $a = "WScript.Shell" ascii wide nocase
                $b = "ShellExecute" ascii wide nocase
                $c = "AutoOpen" ascii wide nocase
                $d = "ms-msdt:" ascii wide nocase
            condition:
                any of them
        }
        """
        try:
            compiled = yara.compile(source=rule_str)
            yara_res = compiled.match(data=raw_bytes)
            for m in yara_res:
                matches.append({"rule": m.rule, "desc": "Règle YARA compilée matchée."})
                risk_engine.add_risk(25, "HAUT", "YARA", f"Matche YARA : {m.rule}")
        except Exception:
            pass

    text_content = raw_bytes[:2000000].decode("latin1", errors="ignore")
    for r in BUILTIN_REGEX_RULES:
        if re.search(r["pattern"], text_content, re.IGNORECASE):
            matches.append({"rule": r["name"], "desc": r["desc"]})
            risk_engine.add_risk(r["risk"], r["severity"], "YARA/Signature", f"Règle [{r['name']}] : {r['desc']}")

    if matches:
        st.warning(f"{len(matches)} signature(s) d'exploit / anomalie(s) YARA détectée(s) :")
        for m in matches:
            st.error(f"**[{m['rule']}]** — {m['desc']}")
    else:
        st.success("Aucune signature YARA ou d'exploit connue matchée.")

    return matches


# ----------------------------------------------------------------------------
# 8. Payload & URL Extractor Engine (Couverture Complète)
# ----------------------------------------------------------------------------

def extract_urls_and_payloads(raw_bytes: bytes, zf: zipfile.ZipFile = None, risk_engine: ForensicRiskEngine = None) -> dict:
    section("Analyse d'URLs & Objets OLE embarqués", "Récolte les liens web/réseau et extrait les binaires en quarantaine.")
    
    urls_found = set()
    raw_str = raw_bytes[:2000000].decode("latin1", errors="ignore")
    
    regex_url = r"(?:https?|ftp|file|ms-msdt|search-ms|mhtml)://[^\s\"'<>]+"
    for m in re.findall(regex_url, raw_str, re.IGNORECASE):
        urls_found.add(m)
        
    suspicious_urls = []
    for url in urls_found:
        if re.search(r"(?:127\.0\.0\.1|localhost|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", url):
            suspicious_urls.append((url, "Adresse IP directe / Hôte brut"))
        elif any(proto in url.lower() for proto in ["ms-msdt:", "file://", "mhtml:", "search-ms:"]):
            suspicious_urls.append((url, "Protocole réseau dangereux"))

    if suspicious_urls:
        st.error(f"{len(suspicious_urls)} URL(s) suspecte(s) ou liens à haut risque détectés :")
        for u, reason in suspicious_urls:
            st.warning(f"**[{reason}]** `{u}`")
            if risk_engine:
                risk_engine.add_risk(25, "HAUT", "URL Suspecte", f"{reason} : {u}")
    elif urls_found:
        st.info(f"{len(urls_found)} URL(s) légitime(s) extraite(s) :")
        for u in list(urls_found)[:10]:
            st.code(u, language="text")
    else:
        st.success("Aucune URL extraite.")

    embedded_files = []
    if zf is not None:
        for name in zf.namelist():
            name_lower = name.lower()
            if "printersettings" in name_lower:
                continue
            ext_n = Path(name_lower).suffix
            if "embeddings/" in name_lower or ext_n in DANGEROUS_PAYLOAD_EXTS:
                bdata = safe_zip_read_bytes(zf, name)
                if bdata:
                    embedded_files.append((name, bdata))
                    if risk_engine:
                        risk_engine.add_risk(30, t("CRITIQUE", "CRITICAL"), "Payload OLE", f"Objet binaire embarqué : {name}")

    if embedded_files:
        st.error(f"{len(embedded_files)} objet(s) binaire(s) OLE / payload(s) embarqué(s) trouvé(s) !")
        for name, bdata in embedded_files:
            b_hash = sha256_of(bdata)
            btn_key = f"embed_{sha256_of(name.encode())[:12]}"
            st.code(f"{name} ({len(bdata)} octets) — SHA-256: {b_hash}", language="text")
            st.download_button(
                f"Télécharger {os.path.basename(name)} (Quarantaine)",
                data=bdata,
                file_name=f"quarantaine_{os.path.basename(name)}",
                key=btn_key
            )
    else:
        st.caption("Aucun objet binaire OLE embarqué résiduel dans l'archive.")

    return {"urls": list(urls_found), "suspicious_urls": suspicious_urls, "embedded_count": len(embedded_files)}


# ----------------------------------------------------------------------------
# 9. Stéganographie ZIP & Commentaires Masqués (Socle d'extensions étendu)
# ----------------------------------------------------------------------------

def inspect_zip_stego_and_comments(zf: zipfile.ZipFile, names: list, risk_engine: ForensicRiskEngine = None):
    section("Stéganographie ZIP & Commentaires Masqués", "Recherche les fichiers masqués dans l'archive ZIP et extrait les commentaires cachés.")
    
    content_types_xml = safe_zip_read(zf, "[Content_Types].xml") or ""
    override_files = set(re.findall(r'PartName="([^"]+)"', content_types_xml))
    default_extensions = set(e.lower() for e in re.findall(r'Extension="([^"]+)"', content_types_xml))
    default_extensions.update({
        "rels", "xml", "png", "jpeg", "jpg", "bin", "bmp", "emf", "wmf", "tif", "tiff", "txt",
        "svg", "webp", "eps", "gif", "ico", "mp4", "mp3", "wav", "dat", "css", "js", "html"
    })

    unreferenced = []
    for n in names:
        if n in ("[Content_Types].xml", "_rels/.rels") or n.endswith(".rels") or "/_rels/" in n or n.startswith("customXml/"):
            continue
        ext = Path(n).suffix.lstrip(".").lower()
        formatted_name = "/" + n if not n.startswith("/") else n
        
        if formatted_name not in override_files and ext not in default_extensions:
            unreferenced.append(n)

    if unreferenced:
        st.error(f"**ALERTE STÉGANOGRAPHIE** : {len(unreferenced)} fichier(s) suspect(s) non-standard présent(s) dans le ZIP !")
        for ufile in unreferenced:
            st.warning(f"Fichier dissimulé / non-standard : `{ufile}`")
            if risk_engine:
                risk_engine.add_risk(25, "HAUT", "Stéganographie ZIP", f"Fichier masqué non référencé : {ufile}")
    else:
        st.success("Tous les composants de l'archive ZIP correspondent aux types et structures OOXML standards.")

    comment_files = [n for n in names if "comments" in n.lower() and n.endswith(".xml")]
    if comment_files:
        st.info(f"{len(comment_files)} fichier(s) de commentaires trouvé(s).")
        for cf in comment_files:
            c_xml = safe_zip_read(zf, cf)
            if c_xml:
                comments_text = re.findall(r"<w:t[^>]*>(.*?)</w:t>", c_xml, re.DOTALL) or re.findall(r"<text[^>]*>(.*?)</text>", c_xml, re.DOTALL)
                if comments_text:
                    st.warning(f"Commentaires extraits de `{cf}` :")
                    for c_t in comments_text:
                        st.text(f"• \"{c_t}\"")


# ----------------------------------------------------------------------------
# Utilitaires généraux & Moteur XML
# ----------------------------------------------------------------------------

def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_cmd(cmd: list, timeout: int = 30) -> str:
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    try:
        result = subprocess.run(
            cmd, capture_output=True, timeout=timeout,
            stdin=subprocess.DEVNULL, env=env
        )
        stdout = result.stdout.decode("utf-8", errors="replace") if result.stdout else ""
        stderr = result.stderr.decode("utf-8", errors="replace") if result.stderr else ""
        out = stdout + stderr
        if "Could not find" in out and "perl" in out:
            return ""
        return out
    except FileNotFoundError:
        return f"[OUTIL NON TROUVÉ dans le PATH : {cmd[0]}. Installe-le ou vérifie le PATH.]"
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT après {timeout}s : {cmd[0]} n'a pas répondu.]"
    except OSError as e:
        return f"[Erreur exécution ({cmd[0]}) : {e}.]"
    except Exception as e:
        return f"[Erreur exécution : {e}]"


def get_pdf_metadata_fallback(raw_bytes: bytes) -> str:
    """Extrait les métadonnées PDF natives en pur Python sans dépendre d'ExifTool."""
    info_lines = []
    try:
        for match in re.finditer(rb"/(Title|Author|Subject|Creator|Producer|CreationDate|ModDate)\s*\(([^)]+)\)", raw_bytes):
            key = match.group(1).decode("latin1", errors="ignore")
            val = match.group(2).decode("latin1", errors="ignore")
            info_lines.append(f"PDF:{key} : {val}")
            
        xmp_match = re.search(rb"<x:xmpmeta.*?</x:xmpmeta>", raw_bytes, re.DOTALL)
        if xmp_match:
            xmp_str = xmp_match.group(0).decode("utf-8", errors="ignore")
            for tag in ["creator", "title", "format", "CreateDate", "ModifyDate", "MetadataDate"]:
                m = re.search(rf"<{tag}[^>]*>([^<]+)</{tag}>", xmp_str, re.IGNORECASE)
                if m:
                    info_lines.append(f"XMP:{tag} : {m.group(1).strip()}")
    except Exception:
        pass
        
    if info_lines:
        return "[Moteur de Secours Pur Python (Air-Gapped)]\n" + "\n".join(info_lines)
    return "[Moteur Pur Python] Aucune métadonnée brute trouvée dans la structure du fichier."


def parse_xml_bytes(content_bytes: bytes) -> ET.Element | None:
    if not content_bytes:
        return None
    try:
        return ET.fromstring(content_bytes)
    except Exception:
        return None


def local_tag(elem) -> str:
    tag = elem.tag if hasattr(elem, 'tag') else str(elem)
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def get_attr_local(elem: ET.Element, attr_name: str) -> str | None:
    for k, v in elem.attrib.items():
        if k == attr_name or k.endswith(":" + attr_name) or (local_tag(k) == attr_name):
            return v
    return None


def findall_local(elem: ET.Element, name: str) -> list:
    return [e for e in elem.iter() if local_tag(e) == name]


def _call_flexible(func, *args, **all_kwargs):
    sig = inspect.signature(func)
    params = list(sig.parameters.items())
    accepted_kwargs = {k: v for k, v in all_kwargs.items() if k in sig.parameters}
    fill_args = list(args)
    for name, p in params[len(args):]:
        if name in accepted_kwargs:
            continue
        if p.default is inspect.Parameter.empty and p.kind in (
            p.POSITIONAL_OR_KEYWORD, p.POSITIONAL_ONLY
        ):
            fill_args.append(all_kwargs.get(name, True))
    return func(*fill_args, **accepted_kwargs)


REQUIRED_CLI_TOOLS = [
    "exiftool", "pdfinfo", "qpdf", "pdftotext", "pdffonts",
    "pdfimages", "pdfdetach", "pdfattach", "pdfseparate", "pdfunite",
    "pdftocairo", "pdftoppm", "pdftops", "pdftohtml", "zstd",
    "pyhanko", "oleid", "olevba", "oletimes", "oleobj",
    "msodde", "rtfobj", "oledir", "olebrowse", "olemap", "olemeta"
]


def find_tool_executable(tool_name: str) -> bool:
    """Checks if a tool exists in system PATH, local tools/ folder, or PyInstaller _MEIPASS bundle."""
    if shutil.which(tool_name) or shutil.which(tool_name + ".exe") or shutil.which(tool_name + ".py"):
        return True
    possible_dirs = []
    if getattr(sys, 'frozen', False):
        meipass = getattr(sys, '_MEIPASS', None)
        if meipass:
            possible_dirs.append(os.path.join(meipass, "tools"))
            possible_dirs.append(meipass)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    possible_dirs.append(os.path.join(base_dir, "tools"))
    possible_dirs.append(base_dir)
    
    for d in possible_dirs:
        for ext in ["", ".exe", ".py", ".bat", ".cmd"]:
            candidate = os.path.join(d, tool_name + ext)
            if os.path.isfile(candidate):
                return True
    return False


@st.cache_resource(show_spinner=False)
def check_dependencies() -> dict:
    status = {}
    for tool in REQUIRED_CLI_TOOLS:
        status[tool] = find_tool_executable(tool)
    
    status["pdfid"] = find_tool_executable("pdfid") or find_tool_executable("pdfid.py")
    status["yara-python"] = YARA_AVAILABLE
    status["pillow-ela"] = PIL_AVAILABLE
    
    try:
        import extract_msg
        status["extract_msg"] = True
    except ImportError:
        status["extract_msg"] = False
        
    try:
        import lxml
        status["lxml"] = True
    except ImportError:
        status["lxml"] = False
        
    try:
        import cryptography
        status["cryptography"] = True
    except ImportError:
        status["cryptography"] = False
        
    try:
        import reportlab
        status["reportlab"] = True
    except ImportError:
        status["reportlab"] = False
        
    return status


def render_dependency_check():
    status = check_dependencies()
    missing = [t for t, ok in status.items() if not ok]
    with st.expander(f"{t('Dépendances externes', 'External dependencies')} ({len(status) - len(missing)}/{len(status)} {t('disponibles', 'available')})", expanded=bool(missing)):
        cols = st.columns(6)
        for i, (tool, ok) in enumerate(sorted(status.items())):
            status_label = t("OK", "OK") if ok else t("MANQUANT", "MISSING")
            cols[i % 6].write(f"{status_label} — {tool}")
        if missing:
            st.warning(
                t("Outil(s) non localisé(s) dans le dossier tools/ local ou le PATH système : ", "Tool(s) not located in local tools/ folder or system PATH: ") + ", ".join(sorted(missing)) +
                t(". Les fonctionnalités associées utiliseront les moteurs de secours intégrés.", ". Associated features will use built-in fallback engines.")
            )


# ----------------------------------------------------------------------------
# Helpers PDF & Poppler / PyHanko / ExifTool
# ----------------------------------------------------------------------------

@st.cache_resource(show_spinner=False)
def resolve_pdfid_script_path():
    possible_paths = []
    if getattr(sys, 'frozen', False):
        meipass = getattr(sys, '_MEIPASS', None)
        if meipass:
            possible_paths.append(os.path.join(meipass, "tools", "pdfid.py"))
            possible_paths.append(os.path.join(meipass, "pdfid.py"))
            
    base_dir = os.path.dirname(os.path.abspath(__file__))
    possible_paths.append(os.path.join(base_dir, "tools", "pdfid.py"))
    possible_paths.append(os.path.join(base_dir, "pdfid.py"))
    
    which_path = shutil.which("pdfid.py")
    if which_path: possible_paths.append(which_path)

    for p in possible_paths:
        if p and os.path.isfile(p):
            return p

    for candidate_dir in ("C:\\Tools", os.path.expanduser("~\\Tools"), "C:\\Tools\\DidierStevensSuite"):
        candidate = os.path.join(candidate_dir, "pdfid.py")
        if os.path.isfile(candidate):
            return candidate
    return None


def run_pdfid_via_api(pdf_path: str) -> str:
    if not pdf_path:
        return "[Aucun chemin de fichier fourni pour pdfid.]"
    try:
        from pdfid.pdfid import PDFiD, PDFiD2String
    except ImportError:
        try:
            from pdfid import PDFiD, PDFiD2String
        except Exception as e:
            return f"[pdfid : impossible d'utiliser le module ({type(e).__name__}: {e}).]"
    try:
        xml_doc = _call_flexible(
            PDFiD, pdf_path,
            allNames=False, extraData=False, disarm=False, force=True
        )
        return _call_flexible(PDFiD2String, xml_doc, force=True)
    except Exception as e:
        return f"[pdfid : erreur pendant l'analyse ({type(e).__name__}: {e}).]"


def run_pdfid_safe(pdf_path: str) -> str:
    api_result = run_pdfid_via_api(pdf_path)
    if not api_result.startswith("[pdfid :"):
        return api_result
    script_path = resolve_pdfid_script_path()
    if script_path:
        cmd_result = run_cmd([sys.executable, script_path, pdf_path], timeout=60)
        if "[Erreur" not in cmd_result and "TIMEOUT" not in cmd_result:
            return cmd_result
    return api_result


def is_password_protected(out: str) -> bool:
    return "Incorrect password" in out or "invalid password" in out.lower() or "command line error" in out.lower()


def run_poppler_safe(cmd: list, timeout: int = 60) -> str:
    out = run_cmd(cmd, timeout=timeout)
    if is_password_protected(out):
        tool = os.path.basename(cmd[0]).lower()
        new_cmd = (cmd[:1] + ["--password="] + cmd[1:]) if tool == "qpdf" else (cmd[:1] + ["-upw", ""] + cmd[1:])
        out2 = run_cmd(new_cmd, timeout=timeout)
        if not is_password_protected(out2):
            return out2 + "\n\n[Note : fichier ouvert avec mot de passe vide.]"
        return out + "\n\n[Ce PDF nécessite un vrai mot de passe non vide.]"
    return out


def run_pyhanko_safe(path: str) -> str:
    out = run_cmd(["pyhanko", "sign", "validate", "--pretty-print", path], timeout=20)
    if "TIMEOUT" in out or is_password_protected(out):
        out2 = run_cmd(["pyhanko", "sign", "validate", "--pretty-print", "--password", "", path], timeout=20)
        if "TIMEOUT" not in out2:
            return out2
        return "[Le PDF est protégé par mot de passe, validation impossible sans le vrai mot de passe.]"
    return out


def explain(text):
    st.info(f"POURQUOI C'EST UTILE : {text}")


def section(title, help_text):
    st.subheader(title)
    explain(help_text)


def html_escape_local(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


RSID_PALETTE = [
    "#FFD966", "#93C47D", "#76A5AF", "#E06666", "#C27BA0",
    "#8E7CC3", "#F6B26B", "#6FA8DC", "#B4A7D6", "#D5A6BD",
]

RSID_TEXT_COLOR = "#111111"
RSID_DOMINANT_BORDER = "1px solid #999;"


# ----------------------------------------------------------------------------
# Report Collector JSON Export
# ----------------------------------------------------------------------------

class ReportCollector:
    def __init__(self, filename: str, file_hash: str):
        self.data = {
            "meta": {
                "filename": filename,
                "sha256": file_hash,
                "generated_at_utc": datetime.now(timezone.utc).isoformat(),
                "tool": "forensic_doc_analyzer_patched.py v1.0.0",
            },
            "findings": {},
        }

    def add(self, section_key: str, payload):
        self.data["findings"][section_key] = payload

    def to_json(self) -> str:
        return json.dumps(self.data, indent=2, ensure_ascii=False, default=str)


def render_report_export(collector: "ReportCollector", filename: str = "", file_hash: str = "", risk_engine: ForensicRiskEngine = None, timeline: ForensicTimelineEngine = None):
    st.divider()
    st.subheader("Exports du rapport d'analyse")
    explain("Télécharge soit le fichier JSON brut pour intégration SIEM/SOC, soit le Rapport d'Analyse Forensique Horodaté (HTML/PDF imprimable).")
    
    c1, c2 = st.columns(2)
    with c1:
        report_json = collector.to_json()
        st.download_button(
            label="📥 Télécharger le rapport JSON (Données brutes / SIEM)",
            data=report_json.encode("utf-8"),
            file_name=f"rapport_forensique_{file_hash[:12]}.json",
            mime="application/json",
        )
    with c2:
        if risk_engine and timeline:
            legal_html = generate_legal_grade_report_html(filename, file_hash, risk_engine, timeline, collector)
            st.download_button(
                label="⚖️ Télécharger le Rapport d'Analyse Forensique Horodaté (HTML/PDF Imprimable)",
                data=legal_html.encode("utf-8"),
                file_name=f"rapport_forensique_{file_hash[:12]}.html",
                mime="text/html",
            )

    with st.expander("Aperçu du rapport JSON"):
        st.code(collector.to_json()[:5000], language="json")


# ----------------------------------------------------------------------------
# Lecture ZIP et EXIF images
# ----------------------------------------------------------------------------

def safe_zip_read(zf: zipfile.ZipFile, name: str, encoding="utf-8"):
    try:
        return zf.read(name).decode(encoding, errors="replace")
    except KeyError:
        return None
    except zipfile.BadZipFile as e:
        st.warning(f"Archive corrompue lors de la lecture de {name} : {e}")
        return None
    except Exception as e:
        st.warning(f"Erreur inattendue lors de la lecture de {name} : {e}")
        return None


def safe_zip_read_bytes(zf: zipfile.ZipFile, name: str):
    try:
        return zf.read(name)
    except Exception as e:
        st.warning(f"Erreur inattendue lors de la lecture binaire de {name} : {e}")
        return None


def extract_image_exif(image_bytes: bytes, filename: str) -> dict:
    if not image_bytes or shutil.which("exiftool") is None:
        return {}
    suffix = Path(filename).suffix or ".jpg"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(image_bytes)
        tmp_path = tmp.name
    try:
        cmd_out = run_cmd(["exiftool", "-G1", "-a", "-s", tmp_path], timeout=15)
        metadata = {}
        for line in cmd_out.splitlines():
            if ":" in line:
                parts = line.split(":", 1)
                key = parts[0].strip()
                val = parts[1].strip()
                if any(tag in key.lower() for tag in ["date", "gps", "model", "make", "software", "artist", "copyright", "owner", "serial", "create"]):
                    metadata[key] = val
        return metadata
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


# ----------------------------------------------------------------------------
# RSID & Analysis helpers
# ----------------------------------------------------------------------------

def parse_docx_paragraphs_with_rsid(doc_xml: str) -> list:
    if not doc_xml:
        return []

    root = parse_xml_bytes(doc_xml.encode("utf-8", errors="ignore"))
    if root is None:
        paragraphs_xml = re.findall(r"<w:p\b[^>]*>.*?</w:p>", doc_xml, re.DOTALL)
        result = []
        for p_xml in paragraphs_xml:
            p_rsid_match = re.search(r'<w:p\b[^>]*w:rsidR="([0-9A-Fa-f]+)"', p_xml)
            p_rsidpr_match = re.search(r'<w:p\b[^>]*w:rsidRPr="([0-9A-Fa-f]+)"', p_xml)
            default_rsid = p_rsid_match.group(1) if p_rsid_match else None
            para_rsidpr = p_rsidpr_match.group(1) if p_rsidpr_match else None
            runs = re.findall(r"<w:r\b[^>]*>.*?</w:r>", p_xml, re.DOTALL)
            run_segments = []
            for r_xml in runs:
                run_rsid_match = re.search(r'<w:r\b[^>]*w:rsidR="([0-9A-Fa-f]+)"', r_xml)
                run_rsidpr_match = re.search(r'<w:r\b[^>]*w:rsidRPr="([0-9A-Fa-f]+)"', r_xml)
                run_text = "".join(re.findall(r"<w:t[^>]*>(.*?)</w:t>", r_xml, re.DOTALL))
                if not run_text:
                    continue
                has_explicit_rsidR = run_rsid_match is not None
                run_rsidpr = run_rsidpr_match.group(1) if run_rsidpr_match else None
                effective_rsid = run_rsid_match.group(1) if run_rsid_match else (run_rsidpr if run_rsidpr else default_rsid)
                is_formatting_only = (
                    not has_explicit_rsidR and run_rsidpr is not None and
                    para_rsidpr is not None and run_rsidpr != para_rsidpr
                )
                run_segments.append({"text": run_text, "rsid": effective_rsid, "formatting_only": is_formatting_only})
            if run_segments:
                result.append(run_segments)
        return result

    result = []
    for p_elem in findall_local(root, "p"):
        p_rsidR = get_attr_local(p_elem, "rsidR")
        p_rsidRPr = get_attr_local(p_elem, "rsidRPr")
        run_segments = []
        for r_elem in findall_local(p_elem, "r"):
            r_rsidR = get_attr_local(r_elem, "rsidR")
            r_rsidRPr = get_attr_local(r_elem, "rsidRPr")
            texts = [t_elem.text for t_elem in findall_local(r_elem, "t") if t_elem.text]
            run_text = "".join(texts)
            if not run_text:
                continue
            has_explicit_rsidR = r_rsidR is not None
            effective_rsid = r_rsidR if r_rsidR else (r_rsidRPr if r_rsidRPr else p_rsidR)
            is_formatting_only = (
                not has_explicit_rsidR and r_rsidRPr is not None and
                p_rsidRPr is not None and r_rsidRPr != p_rsidRPr
            )
            run_segments.append({"text": run_text, "rsid": effective_rsid, "formatting_only": is_formatting_only})
        if run_segments:
            result.append(run_segments)
    return result


def analyze_rsid_mapping(doc_xml: str, declared_rsids: set) -> dict:
    paragraphs = parse_docx_paragraphs_with_rsid(doc_xml)
    content_rsids, formatting_only_rsids = set(), set()
    rsid_paragraph_counts = {}
    for para in paragraphs:
        para_rsids_in_this_para = set()
        for seg in para:
            if not seg["rsid"]:
                continue
            para_rsids_in_this_para.add(seg["rsid"])
            if seg["formatting_only"]:
                formatting_only_rsids.add(seg["rsid"])
            else:
                content_rsids.add(seg["rsid"])
        for rsid in para_rsids_in_this_para:
            rsid_paragraph_counts[rsid] = rsid_paragraph_counts.get(rsid, 0) + 1
    formatting_only_rsids -= content_rsids
    orphan_rsids = (content_rsids | formatting_only_rsids) - declared_rsids
    return {
        "rsid_paragraph_counts": {r: c for r, c in rsid_paragraph_counts.items() if r in content_rsids},
        "orphan_rsids": orphan_rsids,
        "formatting_only_rsids": formatting_only_rsids,
        "total_paragraphs_mapped": len(paragraphs),
        "total_content_sessions": len(content_rsids),
    }


def check_docx_zip_timestamps(zf: zipfile.ZipFile, timeline: ForensicTimelineEngine = None) -> list:
    suspicious = []
    for info in zf.infolist():
        if info.filename.endswith(".xml") and "word/" in info.filename:
            if info.date_time != (1980, 1, 1, 0, 0, 0):
                suspicious.append((info.filename, info.date_time))
                if timeline:
                    y, mo, d, h, mi, s = info.date_time
                    timeline.add_event(f"{y:04d}-{mo:02d}-{d:02d}T{h:02d}:{mi:02d}:{s:02d}", f"ZIP Info ({info.filename})", "ZIP Timestamp Inhabituel", f"Horodatage non-standard du composant XML {info.filename}")
    return suspicious


def render_zip_timestamp_check(zf: zipfile.ZipFile, collector: "ReportCollector" = None, timeline: ForensicTimelineEngine = None):
    section("Timestamps internes de l'archive DOCX", "Des timestamps ZIP inhabituels peuvent justifier une revue de la chaine de production du fichier.")
    suspicious = check_docx_zip_timestamps(zf, timeline)
    if suspicious:
        unique_dates = {dt[:3] for f, dt in suspicious}
        if len(unique_dates) <= 1:
            st.info(f"ℹ️ **Sauvegarde récente uniforme** : Les composants XML portent tous la date courante de sauvegarde ({suspicious[0][1][2]:02d}/{suspicious[0][1][1]:02d}/{suspicious[0][1][0]}). C'est le comportement standard d'un 'Enregistrer sous...' dans MS Word 2019/2021/365 sur Windows 11.")
        else:
            st.warning(f"⚠️ {len(suspicious)} fichier(s) XML avec des timestamps ZIP hétérogènes :")
            for filename, date_tuple in suspicious:
                y, mo, d, h, mi, s = date_tuple
                st.code(f"{filename} : {d:02d}/{mo:02d}/{y} {h:02d}:{mi:02d}:{s:02d}", language="text")
    else:
        st.success("Tous les fichiers XML internes sont a l'epoch ZIP 1980-01-01.")
    if collector is not None:
        collector.add("zip_timestamps_suspicious", [
            {"filename": f, "date_time": list(dt)} for f, dt in suspicious
        ])


def render_rsid_visual_diff(doc_xml: str, declared_rsids: set):
    section("Visualisation des sessions d'edition", "Chaque couleur represente un RSID distinct.")
    paragraphs = parse_docx_paragraphs_with_rsid(doc_xml)
    if not paragraphs:
        st.caption("Aucun texte exploitable trouve dans document.xml.")
        return
    all_rsids = [seg["rsid"] for para in paragraphs for seg in para if seg["rsid"]]
    rsid_counts = {}
    for rsid in all_rsids:
        rsid_counts[rsid] = rsid_counts.get(rsid, 0) + 1
    sorted_rsids = sorted(rsid_counts.items(), key=lambda x: -x[1])
    if not sorted_rsids:
        st.caption("Aucun RSID exploitable au niveau des runs de texte.")
        return
    dominant_rsid = sorted_rsids[0][0]
    color_map = {dominant_rsid: None}
    for palette_idx, (rsid, _) in enumerate(sorted_rsids[1:]):
        color_map[rsid] = RSID_PALETTE[palette_idx % len(RSID_PALETTE)]

    st.markdown("**Legende (session : nb de segments de texte) :**")
    legend_cols = st.columns(min(len(sorted_rsids), 5) or 1)
    for i, (rsid, count) in enumerate(sorted_rsids[:10]):
        col = legend_cols[i % len(legend_cols)]
        color = color_map.get(rsid)
        orphan_flag = " ATTENTION NON DECLARE" if rsid not in declared_rsids and rsid != dominant_rsid else ""
        if color:
            col.markdown(
                f'<span style="background-color:{color};color:{RSID_TEXT_COLOR};'
                f'padding:2px 6px;border-radius:4px;font-weight:600;">{rsid}</span> — {count}{orphan_flag}',
                unsafe_allow_html=True
            )
        else:
            col.markdown(
                f'<span style="background-color:#ffffff;color:{RSID_TEXT_COLOR};'
                f'border:{RSID_DOMINANT_BORDER}padding:2px 6px;border-radius:4px;font-weight:600;">'
                f'{rsid} (dominante)</span> — {count}',
                unsafe_allow_html=True
            )

    display_key = f"rsid_display_mode_{sha256_of(doc_xml[:500].encode())[:12]}"
    display_mode = st.radio(
        "Mode d'affichage du texte",
        ["Surlignage colore", "Soulignement colore (texte neutre)"],
        horizontal=True,
        key=display_key,
    )
    use_underline_mode = display_mode.startswith("Soulignement")

    html_parts = []
    for para in paragraphs:
        para_html = []
        for seg in para:
            text, rsid = html_escape_local(seg["text"]), seg["rsid"]
            color = color_map.get(rsid)
            if color:
                dotted = "border-bottom:2px dotted #333;" if seg["formatting_only"] else ""
                if use_underline_mode:
                    para_html.append(f'<span style="border-bottom:4px solid {color};{dotted}">{text}</span>')
                else:
                    para_html.append(f'<span style="background-color:{color};color:{RSID_TEXT_COLOR};{dotted}">{text}</span>')
            else:
                para_html.append(text)
        html_parts.append("<p>" + "".join(para_html) + "</p>")
    full_html = "<div>" + "".join(html_parts) + "</div>"
    st.markdown(full_html, unsafe_allow_html=True)


def render_rsid_analysis(doc_xml: str, declared_rsids: set, collector: "ReportCollector" = None, risk_engine: ForensicRiskEngine = None):
    section("Cartographie RSID par paragraphe", "Cartographie des RSID effectifs sur les runs de texte.")
    result = analyze_rsid_mapping(doc_xml, declared_rsids)
    if result["total_paragraphs_mapped"] == 0:
        st.caption("Aucun paragraphe exploitable trouve dans document.xml.")
        return
    sorted_counts = sorted(result["rsid_paragraph_counts"].items(), key=lambda x: -x[1])
    st.write(f"{result['total_content_sessions']} RSID de contenu distinct(s) detecte(s), dont {len(sorted_counts)} associe(s) directement a un paragraphe.")
    if result["orphan_rsids"]:
        st.warning(f"{len(result['orphan_rsids'])} RSID présent(s) dans le texte mais absent(s) de la table déclarée : {', '.join(sorted(result['orphan_rsids']))}.")
        if risk_engine:
            risk_engine.add_risk(15, "MOYEN", "RSID Orphelin", f"{len(result['orphan_rsids'])} RSID non déclaré(s) dans settings.xml (Texte copié-collé depuis un document externe ou script)")
    else:
        st.success("Tous les RSID de contenu utilises sont declares dans settings.xml.")
    if collector is not None:
        collector.add("rsid_mapping", result)


def detect_isolated_rsid_runs(doc_xml: str, declared_rsids: set) -> list:
    paragraphs = parse_docx_paragraphs_with_rsid(doc_xml)
    isolated = []
    for para in paragraphs:
        n = len(para)
        if n < 2:
            continue
        for i in range(n):
            curr_rsid = para[i]["rsid"]
            if not curr_rsid:
                continue
            prev_rsid = para[i - 1]["rsid"] if i > 0 else None
            next_rsid = para[i + 1]["rsid"] if i < n - 1 else None
            if i == 0:
                is_isolated = next_rsid is not None and curr_rsid != next_rsid
                context_rsid = next_rsid
            elif i == n - 1:
                is_isolated = prev_rsid is not None and curr_rsid != prev_rsid
                context_rsid = prev_rsid
            else:
                is_isolated = curr_rsid != prev_rsid and prev_rsid == next_rsid
                context_rsid = prev_rsid
            if is_isolated:
                isolated.append({
                    "text": para[i]["text"],
                    "rsid": curr_rsid,
                    "surrounding_rsid": context_rsid,
                    "formatting_only": para[i]["formatting_only"],
                    "position": "debut" if i == 0 else ("fin" if i == n - 1 else "interne"),
                })
    return isolated


def render_isolated_rsid_analysis(doc_xml: str, declared_rsids: set, collector: "ReportCollector" = None):
    section("Mots ou segments isoles avec un RSID different", "Repere les runs dont le RSID differe de leurs voisins immediats.")
    isolated = detect_isolated_rsid_runs(doc_xml, declared_rsids)
    if not isolated:
        st.success("Aucun segment isole avec un RSID divergent detecte.")
    else:
        st.warning(f"{len(isolated)} segment(s) isole(s) avec RSID different :")
        for item in isolated:
            orphan_flag = " ATTENTION NON DECLARE" if item["rsid"] not in declared_rsids else ""
            kind = "formatage seul" if item["formatting_only"] else "contenu"
            st.text(f"[{item['position']}] \"{item['text']}\" — RSID {item['rsid']} ({kind}){orphan_flag} — contexte : RSID {item['surrounding_rsid']}")
    if collector is not None:
        collector.add("isolated_rsid_runs", isolated)


def detect_reformatted_paragraphs(doc_xml: str) -> list:
    paragraphs = re.findall(r"<w:p\b[^>]*>.*?</w:p>", doc_xml, re.DOTALL)
    reformatted = []
    for p_xml in paragraphs:
        rsidR_match = re.search(r'<w:p\b[^>]*w:rsidR="([0-9A-Fa-f]+)"', p_xml)
        rsidRPr_match = re.search(r'<w:p\b[^>]*w:rsidRPr="([0-9A-Fa-f]+)"', p_xml)
        rsidR = rsidR_match.group(1) if rsidR_match else None
        rsidRPr = rsidRPr_match.group(1) if rsidRPr_match else None
        text = "".join(re.findall(r"<w:t[^>]*>(.*?)</w:t>", p_xml, re.DOTALL))
        if text and rsidR and rsidRPr and rsidR != rsidRPr:
            reformatted.append({"text": text, "rsidR": rsidR, "rsidRPr": rsidRPr})
    return reformatted


def render_reformatted_paragraphs_analysis(doc_xml: str, collector: "ReportCollector" = None):
    section("Paragraphes avec RSID de formatage distinct", "Repere les paragraphes dont rsidR et rsidRPr different.")
    reformatted = detect_reformatted_paragraphs(doc_xml)
    if not reformatted:
        st.success("Aucun paragraphe avec un rsidRPr distinct de son rsidR detecte.")
    else:
        st.warning(f"{len(reformatted)} paragraphe(s) avec rsidRPr distinct :")
        for item in reformatted:
            st.text(f"\"{item['text'][:80]}{'...' if len(item['text']) > 80 else ''}\" — rsidR {item['rsidR']}, rsidRPr {item['rsidRPr']}")
    if collector is not None:
        collector.add("reformatted_paragraphs", reformatted)


def parse_docx_paragraphs_with_lang(doc_xml: str) -> list:
    paragraphs = re.findall(r"<w:p\b[^>]*>.*?</w:p>", doc_xml, re.DOTALL)
    result = []
    for p_xml in paragraphs:
        p_lang_match = re.search(r"<w:lang\b[^>]*w:val=\"([A-Za-z\-]+)\"", p_xml)
        default_lang = p_lang_match.group(1) if p_lang_match else None
        runs = re.findall(r"<w:r\b[^>]*>.*?</w:r>", p_xml, re.DOTALL)
        run_segments = []
        for r_xml in runs:
            run_lang_match = re.search(r"<w:lang\b[^>]*w:val=\"([A-Za-z\-]+)\"", r_xml)
            run_text = "".join(re.findall(r"<w:t[^>]*>(.*?)</w:t>", r_xml, re.DOTALL))
            if run_text:
                run_segments.append({"text": run_text, "lang": run_lang_match.group(1) if run_lang_match else default_lang})
        if run_segments:
            result.append(run_segments)
    return result


def render_lang_change_analysis(doc_xml: str, collector: "ReportCollector" = None):
    section("Changements de langue (w:lang)", "w:lang correspond a la langue de correction attribuee au texte.")
    paragraphs = parse_docx_paragraphs_with_lang(doc_xml)
    if not paragraphs:
        st.caption("Aucun texte exploitable trouve pour l'analyse de langue.")
        return
    all_langs = {seg["lang"] for para in paragraphs for seg in para if seg["lang"]}
    if len(all_langs) <= 1:
        st.success(f"Une seule langue detectee : **{next(iter(all_langs)) if all_langs else 'non specifiee'}**.")
        return
    transitions = []
    for para in paragraphs:
        for prev_seg, seg in zip(para, para[1:]):
            if prev_seg["lang"] != seg["lang"]:
                transitions.append((prev_seg, seg))
    st.warning(f"{len(all_langs)} langues distinctes detectees : {', '.join(sorted(all_langs))}. {len(transitions)} transition(s) entre runs.")
    if transitions:
        with st.expander(f"Voir les {len(transitions)} transition(s) de langue"):
            for before, after in transitions:
                st.text(f"[{before['lang']}] \"{before['text']}\" -> [{after['lang']}] \"{after['text']}\"")
    if collector is not None:
        collector.add("lang_changes", {
            "languages": sorted(all_langs),
            "transition_count": len(transitions),
        })


def analyze_rsid_root(names: list, zf: zipfile.ZipFile) -> dict:
    if "word/settings.xml" not in names:
        return {"rsid_root": None}
    settings_xml = safe_zip_read(zf, "word/settings.xml")
    if settings_xml is None:
        return {"rsid_root": None}
    root_match = re.search(r'<w:rsidRoot\b[^>]*w:val="([0-9A-Fa-f]+)"', settings_xml)
    return {"rsid_root": root_match.group(1) if root_match else None}


def render_rsid_root_and_style_check(names: list, zf: zipfile.ZipFile, doc_xml: str, collector: "ReportCollector" = None):
    section("RSID racine (rsidRoot)", "rsidRoot marque la session dans laquelle le document a ete cree.")
    root_info = analyze_rsid_root(names, zf)
    rsid_root = root_info["rsid_root"]
    if not rsid_root:
        st.caption("Aucun rsidRoot trouve dans settings.xml.")
        return
    st.info(f"rsidRoot declare : **{rsid_root}**")
    paragraphs = parse_docx_paragraphs_with_rsid(doc_xml)
    all_observed = {seg["rsid"] for para in paragraphs for seg in para if seg["rsid"]}
    if all_observed and rsid_root not in all_observed:
        st.warning(
            f"Le rsidRoot ({rsid_root}) n'apparait dans aucun run de texte observe. "
            "Cela peut indiquer un copier-coller massif ou une reconstruction du document."
        )
    elif all_observed:
        st.success("Le rsidRoot declare apparait bien parmi les RSID observes dans le texte.")
    if collector is not None:
        collector.add("rsid_root", {"rsid_root": rsid_root, "found_in_text": rsid_root in all_observed if all_observed else None})


def render_docid_and_protection_check(names: list, zf: zipfile.ZipFile, collector: "ReportCollector" = None) -> str:
    section("Identifiant de document (docId) et protections", "Extrait le docId Office et les protections declarees dans settings.xml.")
    doc_id = None
    if "word/settings.xml" in names:
        settings_xml = safe_zip_read(zf, "word/settings.xml")
        if settings_xml is not None:
            docid_match = re.search(r'w1[45]:docId\s+w1[45]:val="(\{[0-9A-Fa-f\-]+\})"', settings_xml)
            if docid_match:
                doc_id = docid_match.group(1)
                st.info(f"docId : **{doc_id}**")
            else:
                st.caption("Aucun w15:docId trouve.")
            protect_match = re.search(r'<w:documentProtection\b([^>]*)/?>', settings_xml)
            if protect_match:
                attrs = protect_match.group(1)
                edit_match = re.search(r'w:edit="([^"]+)"', attrs)
                algo_match = re.search(r'w:algorithmName="([^"]+)"', attrs)
                st.warning(f"Protection active : mode = **{edit_match.group(1) if edit_match else '?'}**, algo = **{algo_match.group(1) if algo_match else 'non specifie'}**.")
            else:
                st.success("Aucune protection de document active.")
    if collector is not None:
        collector.add("doc_id", doc_id)
    return doc_id


def render_hidden_content_controls(doc_xml: str, collector: "ReportCollector" = None):
    section("Contenus caches (vanish, sdtContent, etc.)", "Recherche des marqueurs de texte cache ou de controles de contenu structures.")
    vanish_count = len(re.findall(r"<w:vanish\b", doc_xml))
    sdt_count = len(re.findall(r"<w:sdt\b", doc_xml))
    if vanish_count:
        st.warning(f"{vanish_count} marqueur(s) de texte cache (w:vanish) detecte(s).")
    else:
        st.success("Aucun texte marque comme cache (w:vanish).")
    if sdt_count:
        st.info(f"{sdt_count} controle(s) de contenu structure (w:sdt) detecte(s).")
    if collector is not None:
        collector.add("hidden_content", {"vanish_count": vanish_count, "sdt_count": sdt_count})


def detect_hidden_or_fake_redaction_text(doc_xml: str, collector: "ReportCollector" = None, risk_engine: ForensicRiskEngine = None):
    section("Détection du texte masqué et des faux caviardages", "Recherche le texte blanc, micro-polices (< 2pt), ou formes géométriques noires superposées.")
    if not doc_xml:
        return
    findings = []
    root = parse_xml_bytes(doc_xml.encode("utf-8", errors="ignore"))
    if root is not None:
        for p_elem in findall_local(root, "p"):
            for r_elem in findall_local(p_elem, "r"):
                t_texts = [t.text for t in findall_local(r_elem, "t") if t.text]
                text = "".join(t_texts)
                if not text.strip():
                    continue
                rPr = findall_local(r_elem, "rPr")
                if rPr:
                    pr = rPr[0]
                    if findall_local(pr, "vanish") or findall_local(pr, "webHidden"):
                        findings.append({"type": "Texte caché (w:vanish)", "text": text, "detail": "Attribut w:vanish présent."})
                        if risk_engine: risk_engine.add_risk(15, "MOYEN", "Masquage Texte", "Attribut w:vanish sur du texte")
                    color_elems = findall_local(pr, "color")
                    if color_elems:
                        c_val = get_attr_local(color_elems[0], "val")
                        if c_val and c_val.upper() in ("FFFFFF", "AUTO"):
                            shd_elems = findall_local(pr, "shd")
                            shd_val = get_attr_local(shd_elems[0], "fill") if shd_elems else None
                            if c_val.upper() == "FFFFFF" or (shd_val and shd_val.upper() == "FFFFFF"):
                                findings.append({"type": "Texte blanc / Camouflé", "text": text, "detail": f"Couleur texte={c_val}, Fond={shd_val}"})
                                if risk_engine: risk_engine.add_risk(20, "HAUT", "Texte Camouflé", "Texte blanc sur fond blanc")
                    sz_elems = findall_local(pr, "sz")
                    if sz_elems:
                        sz_val = get_attr_local(sz_elems[0], "val")
                        if sz_val and sz_val.isdigit() and int(sz_val) <= 4:
                            findings.append({"type": "Micro-police (< 2pt)", "text": text, "detail": f"Taille sz={sz_val} ({int(sz_val)/2} pt)"})
                            if risk_engine: risk_engine.add_risk(15, "MOYEN", "Micro-police", "Taille police < 2pt")

    drawings = re.findall(r"<(?:v:rect|v:shape|w:drawing)\b[^>]*>", doc_xml)
    black_rects = [d for d in drawings if "fillcolor=\"black\"" in d.lower() or "#000000" in d.lower()]
    if black_rects:
        findings.append({"type": "Forme de caviardage suspecte", "text": f"{len(black_rects)} forme(s) noire(s)", "detail": "Des formes noires sont superposées sans suppression du texte."})
        if risk_engine: risk_engine.add_risk(25, "HAUT", "Faux Caviardage", f"{len(black_rects)} formes noires superposées sur du texte XML non effacé !")

    if findings:
        st.warning(f"{len(findings)} anomalie(s) de masquage ou caviardage détectée(s) :")
        for item in findings:
            st.error(f"**[{item['type']}]** \"{item['text'][:100]}\" — {item['detail']}")
    else:
        st.success("Aucune anomalie évidente de masque (texte blanc, micro-police ou forme noire suspecte) détectée.")
    if collector is not None:
        collector.add("stealth_redaction_findings", findings)


def analyze_docx_templates_and_printers(zf: zipfile.ZipFile, names: list, collector: "ReportCollector" = None, risk_engine: ForensicRiskEngine = None):
    section("Modèles distants (attachedTemplate) et Paramètres d'impression", "Recherche des modèles Word externes (UNC/distants) et des traces d'imprimantes locales.")
    template_targets = []
    for rel_name in [n for n in names if n.endswith("settings.xml.rels") or n.endswith("webSettings.xml.rels")]:
        content = safe_zip_read(zf, rel_name)
        if content:
            matches = re.findall(r'Type="[^"]*attachedTemplate"[^>]*Target="([^"]+)"', content)
            for m in matches:
                template_targets.append((rel_name, m))

    if template_targets:
        for rel, target in template_targets:
            if target.startswith("\\\\") or target.startswith("http://") or target.startswith("https://"):
                st.error(f"**ALERTE INJECTION / MODÈLE DISTANT** dans `{rel}` -> `{target}`")
                if risk_engine: risk_engine.add_risk(30, t("CRITIQUE", "CRITICAL"), "Modèle Distant", f"attachedTemplate UNC/Web : {target}")
            else:
                st.warning(f"Modèle attaché dans `{rel}` -> `{target}`")
    else:
        st.success("Aucun modèle attaché externe (attachedTemplate) détecté.")

    printer_files = [n for n in names if "printerSettings" in n]
    printer_strings = []
    if printer_files:
        st.info(f"{len(printer_files)} fichier(s) de paramètres d'impression (`printerSettings*.bin`) trouvé(s).")
        for pf in printer_files:
            bin_data = safe_zip_read_bytes(zf, pf)
            if bin_data:
                found = re.findall(rb"[\x20-\x7E]{4,}", bin_data)
                clean_found = [f.decode('ascii', errors='ignore') for f in found if len(f.strip()) > 3]
                if clean_found:
                    st.caption(f"Traces extraites de {pf} :")
                    st.code("\n".join(clean_found[:10]), language="text")
                    printer_strings.append({"file": pf, "strings": clean_found[:20]})
    else:
        st.caption("Aucun fichier printerSettings.bin présent.")


# ----------------------------------------------------------------------------
# PDF Revision & Watermarks
# ----------------------------------------------------------------------------

PDFID_GLOSSARY = {
    "/JavaScript": "Code JavaScript embarqué, potentiellement exécuté à l'ouverture.",
    "/JS": "Alias de /JavaScript.",
    "/AA": "Actions automatiques déclenchées par des événements du document.",
    "/OpenAction": "Action exécutée automatiquement à l'ouverture du PDF.",
    "/AcroForm": "Formulaire interactif présent dans le document.",
    "/JBIG2Decode": "Filtre de compression d'image parfois associé à des vulnérabilités connues.",
    "/RichMedia": "Contenu multimédia riche (Flash, vidéo) embarqué.",
    "/Launch": "Action pouvant lancer un programme ou un fichier externe.",
    "/EmbeddedFile": "Fichier arbitraire embarqué dans le PDF.",
    "/XFA": "Formulaire XFA (Adobe), source fréquente de vulnérabilités.",
    "/URI": "Lien hypertexte embarqué, potentiellement vers une ressource externe.",
    "/SubmitForm": "Action de soumission de formulaire, potentiellement vers un serveur externe.",
    "/GoToR": "Action de navigation vers une ressource externe (autre fichier).",
    "/ObjStm": "Flux d'objets compressés, peut masquer du contenu à une inspection superficielle.",
}


def render_pdfid_glossary(pdfid_out: str):
    present_markers = []
    for marker in PDFID_GLOSSARY:
        for line in pdfid_out.splitlines():
            if marker in line:
                parts = line.split()
                if parts and parts[-1].lstrip("-").isdigit() and int(parts[-1]) > 0:
                    present_markers.append((marker, int(parts[-1])))
                break
    if not present_markers:
        st.caption("Aucun marqueur actif/suspect présent dans ce document.")
        return
    st.markdown("**Explication des éléments détectés ci-dessus :**")
    for marker, count in present_markers:
        st.info(f"**{marker}** ({count}x) : {PDFID_GLOSSARY[marker]}")


def analyze_pdf_revisions(path: str, raw: bytes, collector: "ReportCollector" = None, risk_engine: ForensicRiskEngine = None, timeline: ForensicTimelineEngine = None):
    section("Analyse des révisions incrémentales PDF (Historique %%EOF)", "Extrait et compare les versions antérieures du PDF sauvegardées avant chaque marqueur %%EOF.")
    eof_offsets = []
    start = 0
    while True:
        pos = raw.find(b"%%EOF", start)
        if pos == -1:
            break
        eof_offsets.append(pos + 5)
        start = pos + 5

    if len(eof_offsets) <= 1:
        st.success("Un seul marqueur %%EOF trouvé : aucune révision incrémentale antérieure détectable.")
        return

    st.warning(f"**{len(eof_offsets)} révisions incrémentales** identifiées dans la structure du PDF.")
    if risk_engine: risk_engine.add_risk(15, "MOYEN", "PDF Incrémental", f"{len(eof_offsets)} révisions incrémentales trouvées dans le PDF")

    revision_data = []
    for idx, end_offset in enumerate(eof_offsets):
        rev_bytes = raw[:end_offset]
        rev_size = len(rev_bytes)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp_rev:
            tmp_rev.write(rev_bytes)
            tmp_rev_path = tmp_rev.name
        try:
            pdfinfo_out = run_poppler_safe(["pdfinfo", tmp_rev_path], timeout=15)
            txt_out = run_poppler_safe(["pdftotext", "-layout", tmp_rev_path, "-"], timeout=15)
            pages_match = re.search(r"Pages:\s+(\d+)", pdfinfo_out)
            pages = pages_match.group(1) if pages_match else "?"
            mod_date_match = re.search(r"ModDate:\s+(.+)", pdfinfo_out)
            mod_date = mod_date_match.group(1).strip() if mod_date_match else "Inconnue"
            
            if timeline and mod_date != "Inconnue":
                timeline.add_event(mod_date, f"PDF Révision #{idx+1}", "Revision Date", f"Date de modification enregistrée pour la révision #{idx+1}")

            revision_data.append({
                "revision": idx + 1,
                "size_bytes": rev_size,
                "pages": pages,
                "mod_date": mod_date,
                "text_snippet": txt_out[:1000],
                "text_len": len(txt_out.strip())
            })
        finally:
            try:
                os.unlink(tmp_rev_path)
            except OSError:
                pass

    cols = st.columns(min(len(revision_data), 4))
    for idx, rev in enumerate(revision_data):
        col = cols[idx % len(cols)]
        with col:
            st.metric(f"Révision #{rev['revision']}", f"{rev['size_bytes'] / 1024:.1f} Ko", delta=f"{rev['pages']} page(s)")
            st.caption(f"Date modif : {rev['mod_date']}")
            st.caption(f"Texte : {rev['text_len']} caractères")
            with st.expander(f"Extrait texte (Révision #{rev['revision']})"):
                st.text(rev['text_snippet'] or "(Aucun texte extrait)")

    if collector is not None:
        collector.add("pdf_revisions", revision_data)


def analyze_watermark_indicators(raw: bytes, exiftool_out: str, collector: "ReportCollector" = None):
    section("Indicateurs de watermarking / tracage", "Recherche des marqueurs de traçage ou de filigrane.")
    standard_pdf_fields = {"exiftoolversion", "filename", "directory", "filesize", "filemodifydate", "fileaccessdate",
                            "filecreatedate", "filepermissions", "filetype", "filetypeextension", "mimetype",
                            "pdfversion", "linearized", "author", "copyright", "createdate", "producer", "title",
                            "pagemode", "pagecount", "creator", "moddate", "subject", "keywords", "trapped", "xmptoolkit"}
    suspicious_fields = []
    for line in exiftool_out.splitlines():
        match = re.match(r"\[PDF\]\s+(\w+)\s*:\s*(.+)", line)
        if match and match.group(1).lower() not in standard_pdf_fields:
            suspicious_fields.append((match.group(1), match.group(2).strip()))
    if suspicious_fields:
        for name, value in suspicious_fields:
            st.warning(f"Champ non-standard détecté : **{name}** = `{value}`")
    else:
        st.success("Aucun champ de métadonnées non-standard détecté.")

    email_pattern = re.findall(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", raw[:2000000])
    unique_emails = sorted(set(e.decode(errors="replace") for e in email_pattern))
    if unique_emails:
        st.warning(f"{len(unique_emails)} adresse(s) email trouvée(s) en clair :")
        for email in unique_emails[:20]:
            st.code(email, language="text")
    else:
        st.success("Aucune adresse email en texte clair trouvée.")

    id_like_pattern = re.findall(
        rb"(?:UserID|UID|RecipientID|WatermarkID|TrackID|LicenseID|CustomerID)[:=\s\"']{1,3}([A-Za-z0-9\-_]{4,40})",
        raw[:2000000], re.IGNORECASE
    )
    if id_like_pattern:
        st.warning(f"{len(id_like_pattern)} identifiant(s) potentiel(s) trouvé(s) près de mots-clés de traçage :")
        for match in id_like_pattern[:20]:
            st.code(match.decode(errors="replace"), language="text")

    if collector is not None:
        collector.add("watermark_indicators", {
            "suspicious_metadata_fields": [{"name": n, "value": v} for n, v in suspicious_fields],
            "emails_found": unique_emails,
            "tracking_ids_found": [m.decode(errors="replace") for m in id_like_pattern[:50]],
        })

    section("Attaque de collusion (si tu as une 2e copie)", "Compare deux copies supposées du même document pour localiser les différences binaires.")
    second_file = st.file_uploader("Fichier PDF de comparaison (Collusion)", type=["pdf"], key="collusion_compare")
    if second_file is not None:
        raw2 = second_file.read()
        min_len, block_size = min(len(raw), len(raw2)), 256
        diff_blocks = [offset for offset in range(0, min_len, block_size) if raw[offset:offset + block_size] != raw2[offset:offset + block_size]]
        if diff_blocks:
            st.warning(f"{len(diff_blocks)} bloc(s) de {block_size} octets différent(s).")
            for offset in diff_blocks[:30]:
                st.code(f"Offset {offset}:\n  Fichier 1: {raw[offset:offset + 64]}\n  Fichier 2: {raw2[offset:offset + 64]}", language="text")
        else:
            st.success("Aucune différence binaire trouvée dans la portion comparable.")


# ----------------------------------------------------------------------------
# Format Processors (PDF, DOCX, XLSX, OLE, EML)
# ----------------------------------------------------------------------------

def is_valid_person_name(name: str) -> bool:
    if not name or name in ("Non spécifié", "Non spécifiée"):
        return False
    if re.search(r"\d{4}[:/\-]\d{2}[:/\-]\d{2}", name):
        return False
    return True


def render_metadata_summary_badge(meta_summary: dict):
    if not meta_summary:
        return
        
    st.subheader("👤 Identité des Auteurs & Métadonnées d'Origine")
    
    creator = meta_summary.get("creator", "Non spécifié")
    modifier = meta_summary.get("last_modified_by", "Non spécifié")
    company = meta_summary.get("company", "Non spécifiée")
    revision = meta_summary.get("revision", "Non spécifiée")
    total_time = meta_summary.get("total_edit_time", "Non spécifié")
    doc_id = meta_summary.get("doc_id", "Non spécifié")
    tools = meta_summary.get("tools_detected", [])

    c1, c2, c3 = st.columns(3)
    with c1:
        st.metric("Auteur / Créateur d'origine", creator)
        st.metric("Société / Organisation", company)
    with c2:
        st.metric("Dernier Modificateur", modifier)
        st.metric("Temps d'édition total", total_time)
    with c3:
        st.metric("Compteur de révisions", revision)
        st.metric("Identifiant (docId)", doc_id[:18] + "..." if len(doc_id) > 18 else doc_id)

    if is_valid_person_name(creator) and is_valid_person_name(modifier) and creator != modifier:
        st.warning(f"⚠️ **Incohérence des identités** : Le document a été créé par **{creator}** mais modifié en dernier par **{modifier}**.")
    elif is_valid_person_name(creator) and is_valid_person_name(modifier) and creator == modifier:
        st.success(f"✅ **Identités identiques** : Créateur et dernier modificateur sont **{creator}**.")

    if tools:
        st.info(f"🛠️ **Convertisseurs / Outils détectés** : {', '.join(tools)}")


def analyze_pdf(path: str, raw: bytes, collector: "ReportCollector" = None, risk_engine: ForensicRiskEngine = None, timeline: ForensicTimelineEngine = None):
    st.header("Analyse PDF")
    tabs = st.tabs(["📊 Risk, Métadonnées & Provenance", "📜 Révisions incrémentales (%%EOF)", "🛡️ Signatures & Sécurité", "🔍 URLs & Payloads", "🖼️ Images & Analyse ELA (Retouche)", "✍️ Stylométrie & Texte", "🎯 Watermarking & Traces"])

    exiftool_out = run_cmd(["exiftool", "-G1", "-a", "-s", path], timeout=60) or ""
    if not exiftool_out or "Could not find" in exiftool_out or "[OUTIL NON TROUVÉ" in exiftool_out:
        exiftool_out = get_pdf_metadata_fallback(raw)
    txt_out = run_poppler_safe(["pdftotext", "-layout", path, "-"])

    with tabs[0]:
        risk_engine.render_risk_badge()
        if collector:
            render_metadata_summary_badge(collector.data.get("findings", {}).get("metadata_summary", {}))
        run_yara_scan(raw, risk_engine)
        profile_document_converters(raw, exiftool_out, risk_engine)
        
        section("Comptage %%EOF / startxref / /Prev", "Mises a jour incrementales.")
        eof_count = raw.count(b"%%EOF")
        c1, c2, c3 = st.columns(3)
        c1.metric("Occurrences %%EOF", eof_count)
        c2.metric("Occurrences startxref", raw.count(b"startxref"))
        c3.metric("Occurrences /Prev", raw.count(b"/Prev"))

        section("Identifiants de document (/ID)", "Paires d'ID PDF.")
        id_pairs = re.findall(rb"/ID\s*\[\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>", raw)
        for i, (id1, id2) in enumerate(id_pairs):
            st.write(f"Paire #{i + 1} : premier=`{id1.decode()}` / second=`{id2.decode()}`")

        section("Metadonnees (ExifTool)", "Extraction complète ExifTool.")
        st.info("ℹ️ **Information Horodatages ExifTool** : Les lignes `FileModifyDate` / `FileAccessDate` au tout début du bloc ci-dessous représentent la date d'analyse sur le disque temporaire de votre système (`21/08/2026`). Les vraies dates d'origine du document se trouvent dans les balises `[PDF]` ou `[XMP]` plus bas et sont correctement reportées dans la Ligne du Temps Forensique.")
        st.code(exiftool_out, language="text")

        # Filtrage strict pour ne conserver QUE les dates internes du document (et exclure FileModifyDate/FileAccessDate de l'OS hôte)
        filtered_exif_lines = [
            line for line in exiftool_out.splitlines()
            if not any(file_tag in line for file_tag in ["FileModifyDate", "FileAccessDate", "FileCreateDate", "FileInodeChangeDate", "[System]", "[File]"])
        ]
        filtered_exif_out = "\n".join(filtered_exif_lines)

        c_date = re.search(r"(?:CreateDate|CreationDate)\s*:\s*(\d{4}[^\r\n]+)", filtered_exif_out)
        m_date = re.search(r"(?:ModifyDate|ModDate)\s*:\s*(\d{4}[^\r\n]+)", filtered_exif_out)
        if c_date and timeline: timeline.add_event(c_date.group(1).strip(), "ExifTool PDF", "CreateDate", "Date de création interne du PDF")
        if m_date and timeline: timeline.add_event(m_date.group(1).strip(), "ExifTool PDF", "ModifyDate", "Date de modification interne du PDF")

        section("pdfinfo", "Information générale.")
        pdfinfo_out = run_poppler_safe(["pdfinfo", path])
        st.code(pdfinfo_out, language="text")

        section("Polices (pdffonts)", "Polices déclarées.")
        fonts_out = run_poppler_safe(["pdffonts", path])
        st.code(fonts_out, language="text")

        section("Pieces jointes embarquees (pdfdetach)", "Fichiers embarqués.")
        detach_out = run_poppler_safe(["pdfdetach", "-list", path])
        st.code(detach_out, language="text")

        section("Verification structurelle (qpdf --check)", "Contrôle qpdf.")
        qpdf_out = run_poppler_safe(["qpdf", "--check", path])
        st.code(qpdf_out, language="text")

        timeline.render_timeline(collector, risk_engine)

    with tabs[1]:
        analyze_pdf_revisions(path, raw, collector, risk_engine, timeline)

    with tabs[2]:
        section("pdfid - elements actifs ou suspects", "JavaScript et actions automatiques.")
        pdfid_out = run_pdfid_safe(path)
        st.code(pdfid_out, language="text")
        render_pdfid_glossary(pdfid_out)
        
        section("Validation de signature (pyHanko)", "Signatures électroniques.")
        sig_out = run_pyhanko_safe(path)
        if sig_out.strip(): st.code(sig_out, language="text")
        else: st.write("Pas de signature détectée.")

    with tabs[3]:
        extract_urls_and_payloads(raw, risk_engine=risk_engine)

    with tabs[4]:
        section("Extraction des images & Analyse ELA (Error Level Analysis)", "Détection des retouches d'images, ajouts de texte ou collages sur factures et scans via ELA.")
        with tempfile.TemporaryDirectory() as tmpdir:
            prefix = os.path.join(tmpdir, "img")
            run_poppler_safe(["pdfimages", "-all", path, prefix], timeout=90)
            all_images = sorted(Path(tmpdir).glob("img-*"))
            top_images = sorted(all_images, key=lambda p: p.stat().st_size, reverse=True)[:5]
            
            if not top_images:
                st.caption("Aucune image raster extraite du PDF.")
            
            for img_path in top_images:
                img_bytes = img_path.read_bytes()
                c1, c2, c3 = st.columns([1, 1, 1])
                with c1:
                    try: st.image(str(img_path), width=200, caption=f"Original : {img_path.name}")
                    except Exception: st.write(img_path.name)
                with c2:
                    ela_bytes, status_msg = compute_ela_image(img_bytes)
                    if ela_bytes:
                        st.image(ela_bytes, width=200, caption="Carte Thermique ELA")
                        st.caption(f"✅ {status_msg}")
                    else:
                        st.warning(f"⚠️ {status_msg}")
                with c3:
                    exif = extract_image_exif(img_bytes, img_path.name)
                    if exif: st.json(exif)

    with tabs[5]:
        section("Texte extrait (pdftotext)", "Contenu brut.")
        with st.expander("Voir le texte extrait", expanded=True):
            st.text(txt_out[:5000])
        analyze_stylometry(txt_out)

    with tabs[6]:
        analyze_watermark_indicators(raw, exiftool_out, collector)


def analyze_word_modern(path: str, raw: bytes, collector: "ReportCollector" = None, risk_engine: ForensicRiskEngine = None, timeline: ForensicTimelineEngine = None):
    st.header("Analyse Word (DOCX/DOCM)")
    try: zf = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile: st.error("Fichier non ZIP valide."); return

    names = zf.namelist()
    doc_xml = safe_zip_read(zf, "word/document.xml") or ""
    declared_rsids = set(re.findall(r'w:rsid w:val="([0-9A-Fa-f]+)"', safe_zip_read(zf, "word/settings.xml") or ""))

    tabs = st.tabs(["📊 Métadonnées & Provenance", "🛡️ YARA & Signatures", "📝 Sessions RSID & Révisions", "🕵️ Masquage & Stéganographie", "🔗 Modèles & Imprimantes", "🔍 URLs & Payloads OLE", "🖼️ Images & Analyse ELA", "✍️ Stylométrie & Texte"])

    with tabs[0]:
        risk_engine.render_risk_badge()
        if collector:
            render_metadata_summary_badge(collector.data.get("findings", {}).get("metadata_summary", {}))
        profile_document_converters(raw, risk_engine=risk_engine)
        
        section("Metadonnees core.xml / app.xml", "Affiche le créateur, dernier modificateur et métadonnées de l'application.")
        revision_count = None
        if "docProps/core.xml" in names:
            core = safe_zip_read(zf, "docProps/core.xml")
            if core is not None:
                st.code(core, language="xml")
                creator = re.search(r"<dc:creator>(.*?)</dc:creator>", core)
                modifier = re.search(r"<cp:lastModifiedBy>(.*?)</cp:lastModifiedBy>", core)
                created_match = re.search(r"<dcterms:created[^>]*>(.*?)</dcterms:created>", core)
                modified_match = re.search(r"<dcterms:modified[^>]*>(.*?)</dcterms:modified>", core)
                revision_match = re.search(r"<cp:revision>(\d+)</cp:revision>", core)
                
                if creator: st.info(f"Créateur déclaré (`dc:creator`) : **{creator.group(1)}**")
                if modifier: st.info(f"Dernier modificateur (`cp:lastModifiedBy`) : **{modifier.group(1)}**")
                if creator and modifier:
                    if creator.group(1) != modifier.group(1):
                        st.warning(f"Personnes différentes : créateur = **{creator.group(1)}**, dernier modificateur = **{modifier.group(1)}**.")
                    else:
                        st.success(f"Créateur et dernier modificateur identiques : **{creator.group(1)}**.")
                if revision_match:
                    revision_count = int(revision_match.group(1))
                    st.metric("Valeur cp:revision", revision_count)
                if created_match and timeline: timeline.add_event(created_match.group(1), "core.xml", "dcterms:created", "Date de création du DOCX")
                if modified_match and timeline: timeline.add_event(modified_match.group(1), "core.xml", "dcterms:modified", "Date de modification du DOCX")

        if "docProps/app.xml" in names:
            app_xml = safe_zip_read(zf, "docProps/app.xml")
            if app_xml is not None:
                st.code(app_xml, language="xml")
                total_time_match = re.search(r"<TotalTime>(\d+)</TotalTime>", app_xml)
                company_match = re.search(r"<Company>(.*?)</Company>", app_xml)
                if total_time_match:
                    total_minutes = int(total_time_match.group(1))
                    st.metric("Temps total d'édition déclaré", f"{total_minutes // 60}h{total_minutes % 60:02d}min")
                if company_match and company_match.group(1).strip():
                    st.info(f"Champ Company : **{company_match.group(1)}**")

        render_docid_and_protection_check(names, zf, collector)
        render_zip_timestamp_check(zf, collector, timeline)
        timeline.render_timeline(collector, risk_engine)

    with tabs[1]:
        run_yara_scan(raw, risk_engine)
        has_vba = "word/vbaProject.bin" in names
        if has_vba:
            st.warning("Projet de Macro VBA présent dans l'archive (`word/vbaProject.bin`).")
            risk_engine.add_risk(25, "HAUT", "Macro VBA", "Fichier vbaProject.bin présent dans DOCM")

    with tabs[2]:
        st.metric("RSID declares", len(declared_rsids))
        render_rsid_visual_diff(doc_xml, declared_rsids)
        render_rsid_analysis(doc_xml, declared_rsids, collector, risk_engine)
        render_isolated_rsid_analysis(doc_xml, declared_rsids, collector)
        render_reformatted_paragraphs_analysis(doc_xml, collector)
        render_lang_change_analysis(doc_xml, collector)
        render_rsid_root_and_style_check(names, zf, doc_xml, collector)

        section("Suivi des modifications (Track Changes)", "Compte les insertions/suppressions trackées.")
        ins_count = len(re.findall(r"<w:ins\b", doc_xml))
        del_count = len(re.findall(r"<w:del\b", doc_xml))
        st.write(f"Insertions: {ins_count} | Suppressions: {del_count}")
        authors = set(re.findall(r'w:ins[^>]*w:author="([^"]+)"', doc_xml)) | set(re.findall(r'w:del[^>]*w:author="([^"]+)"', doc_xml))
        if authors: st.info(f"Auteur(s) des révisions trackées : {', '.join(sorted(authors))}")

        render_docx_version_comparison(zf, names)

        section("people.xml", "Affiche les personnes éventuellement liées à l'historique de révision.")
        if "word/people.xml" in names:
            people_xml = safe_zip_read(zf, "word/people.xml")
            if people_xml is not None:
                st.code(people_xml, language="xml")
        else:
            st.caption("Aucun people.xml trouvé.")

    with tabs[3]:
        render_hidden_content_controls(doc_xml, collector)
        detect_hidden_or_fake_redaction_text(doc_xml, collector, risk_engine)
        inspect_zip_stego_and_comments(zf, names, risk_engine)

    with tabs[4]:
        analyze_docx_templates_and_printers(zf, names, collector, risk_engine)
        
        section("Relations et references externes (.rels)", "Liens et templates externes.")
        external_targets = []
        for rf in [n for n in names if n.endswith(".rels")]:
            content = safe_zip_read(zf, rf)
            if content:
                external_targets.extend((rf, t) for t in re.findall(r'Target="([^"]+)"[^>]*TargetMode="External"', content))
        if external_targets:
            for rf, target in external_targets[:20]: st.code(f"{rf} -> {target}", language="text")

    with tabs[5]:
        extract_urls_and_payloads(raw, zf, risk_engine)

    with tabs[6]:
        media = [n for n in names if n.startswith("word/media/")]
        st.write(f"{len(media)} image(s) trouvée(s).")
        for m in media[:5]:
            img_bytes = safe_zip_read_bytes(zf, m)
            if img_bytes:
                c1, c2, c3 = st.columns([1, 1, 1])
                with c1:
                    try: st.image(img_bytes, width=200, caption=m)
                    except Exception: st.write(m)
                with c2:
                    ela_bytes, status_msg = compute_ela_image(img_bytes)
                    if ela_bytes:
                        st.image(ela_bytes, width=200, caption="Carte ELA")
                        st.caption(f"✅ {status_msg}")
                    else:
                        st.warning(f"⚠️ {status_msg}")
                with c3:
                    exif = extract_image_exif(img_bytes, m)
                    if exif: st.json(exif)

    with tabs[7]:
        plain_text = "\n".join(" ".join(re.findall(r"<w:t[^>]*>(.*?)</w:t>", p, re.DOTALL)) for p in re.findall(r"<w:p\b[^>]*>.*?</w:p>", doc_xml, re.DOTALL))
        analyze_stylometry(plain_text)


def render_docx_version_comparison(zf: zipfile.ZipFile, names: list):
    section("Comparaison structurelle avec une autre version DOCX", "Compare les RSID et le texte avec une autre version du document.")
    second_file = st.file_uploader("Fichier DOCX de comparaison", type=["docx", "docm"], key="docx_compare_uploader")
    if second_file is None:
        return
    raw2 = second_file.read()
    try:
        zf2 = zipfile.ZipFile(io.BytesIO(raw2))
    except zipfile.BadZipFile:
        st.error("Le fichier n'est pas un ZIP/OOXML valide.")
        return
    names2 = zf2.namelist()
    doc_xml_1 = safe_zip_read(zf, "word/document.xml") or "" if "word/document.xml" in names else ""
    doc_xml_2 = safe_zip_read(zf2, "word/document.xml") or "" if "word/document.xml" in names2 else ""
    rsids_1 = {seg["rsid"] for para in parse_docx_paragraphs_with_rsid(doc_xml_1) for seg in para if seg["rsid"]}
    rsids_2 = {seg["rsid"] for para in parse_docx_paragraphs_with_rsid(doc_xml_2) for seg in para if seg["rsid"]}
    common = rsids_1 & rsids_2
    only_1 = rsids_1 - rsids_2
    only_2 = rsids_2 - rsids_1
    st.write(f"RSID communs : {len(common)} | Unique f1 : {len(only_1)} | Unique f2 : {len(only_2)}")


def analyze_excel_modern(path: str, raw: bytes, collector: "ReportCollector" = None, risk_engine: ForensicRiskEngine = None, timeline: ForensicTimelineEngine = None):
    st.header("Analyse Excel (XLSX/XLSM)")
    try: zf = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile: st.error("Fichier non ZIP valide."); return

    names = zf.namelist()
    workbook_xml = safe_zip_read(zf, "xl/workbook.xml") or ""

    tabs = st.tabs([
        t("📊 Métadonnées & Provenance", "📊 Metadata & Provenance"),
        t("🛡️ YARA & Payloads", "🛡️ YARA & Payloads"),
        t("🧮 Formules & calcChain", "🧮 Formulas & calcChain"),
        t("👁️ Feuilles cachées & AbsPath", "👁️ Hidden Sheets & AbsPath"),
        t("📜 Revisions Legacy", "📜 Legacy Revisions"),
        t("✍️ Séquence des Textes (sharedStrings)", "✍️ Text Sequence (sharedStrings)")
    ])

    with tabs[0]:
        risk_engine.render_risk_badge()
        if collector:
            render_metadata_summary_badge(collector.data.get("findings", {}).get("metadata_summary", {}))
        profile_document_converters(raw, risk_engine=risk_engine)
        
        section("Metadonnees core.xml", "Créateur, modificateur et dates.")
        if "docProps/core.xml" in names:
            core = safe_zip_read(zf, "docProps/core.xml")
            if core is not None:
                st.code(core, language="xml")
                creator = re.search(r"<dc:creator>(.*?)</dc:creator>", core)
                modifier = re.search(r"<cp:lastModifiedBy>(.*?)</cp:lastModifiedBy>", core)
                created_date = re.search(r"<dcterms:created[^>]*>(.*?)</dcterms:created>", core)
                modified_date = re.search(r"<dcterms:modified[^>]*>(.*?)</dcterms:modified>", core)
                
                if creator: st.info(f"Créateur (`dc:creator`) : **{creator.group(1)}**")
                if modifier: st.info(f"Dernier modificateur (`cp:lastModifiedBy`) : **{modifier.group(1)}**")
                if created_date and timeline: timeline.add_event(created_date.group(1), "core.xml", "dcterms:created", "Date création XLSX")
                if modified_date and timeline: timeline.add_event(modified_date.group(1), "core.xml", "dcterms:modified", "Date modif XLSX")

        section("Historique des auteurs et provenance", "Recherche les identifiants auteur/utilisateur dans tous les composants du classeur.")
        author_sources = {}
        author_pattern = re.compile(r'(?P<attribute>userId|author|lastModifiedBy|userName)="(?P<value>[^"]+)"', re.IGNORECASE)
        for name in names:
            if not (name.endswith(".xml") or name.endswith(".rels")): continue
            content = safe_zip_read(zf, name)
            if content is None: continue
            for match in author_pattern.finditer(content):
                value = match.group("value").strip()
                if not value: continue
                attribute = match.group("attribute")
                source = {
                    "file": name,
                    "attribute": attribute,
                    "context": "journal de révisions legacy" if name.startswith("xl/revisions/") else "métadonnée ou composant interne"
                }
                author_sources.setdefault(value, []).append(source)

        if author_sources:
            st.write(f"{len(author_sources)} identifiant(s)/auteur(s) distinct(s) trouvé(s).")
            for author in sorted(author_sources, key=str.casefold):
                sources = author_sources[author]
                rows = [["Fichier interne", "Attribut / balise", "Nature de la source"]]
                seen = set()
                for source in sources:
                    key = (source["file"], source["attribute"], source["context"])
                    if key not in seen:
                        rows.append([source["file"], source["attribute"], source["context"]])
                        seen.add(key)
                st.table(rows)

        timeline.render_timeline(collector, risk_engine)

    with tabs[1]:
        run_yara_scan(raw, risk_engine)
        extract_urls_and_payloads(raw, zf, risk_engine)
        inspect_zip_stego_and_comments(zf, names, risk_engine)

    with tabs[2]:
        section("Formules actives et résultats mis en cache", "Formules et résultats mis en cache.")
        worksheet_files = sorted(name for name in names if name.startswith("xl/worksheets/") and name.endswith(".xml"))
        active_formulas = []
        for wf in worksheet_files:
            sheet_xml = safe_zip_read(zf, wf)
            if sheet_xml:
                for cell_xml in re.findall(r'<c\b[^>]*r="[^"]+"[^>]*>.*?</c>', sheet_xml, re.DOTALL):
                    ref_match = re.search(r'\br="([A-Z]+\d+)"', cell_xml)
                    formula_match = re.search(r'<f[^>]*>(.*?)</f>', cell_xml, re.DOTALL)
                    value_match = re.search(r'<v>(.*?)</v>', cell_xml, re.DOTALL)
                    if ref_match and formula_match:
                        active_formulas.append({"cell": ref_match.group(1), "formula": formula_match.group(1), "cached_value": value_match.group(1) if value_match else None})
        if active_formulas:
            st.write(f"{len(active_formulas)} formule(s) active(s) détectée(s).")
            st.table([["Cellule", "Formule", "Cache"]] + [[f["cell"], "=" + f["formula"], f["cached_value"] or "ABSENT"] for f in active_formulas[:100]])

        section("Cohérence de la chaîne de calcul (calcChain.xml)", "Compare les références de calcChain.xml avec les formules actives.")
        if "xl/calcChain.xml" in names:
            calc_chain_xml = safe_zip_read(zf, "xl/calcChain.xml") or ""
            chain_cells = set(re.findall(r'\br="([A-Z]+\d+)"', calc_chain_xml))
            active_cells = {f["cell"] for f in active_formulas}
            diff_chain = chain_cells - active_cells
            if diff_chain:
                st.warning(f"Cellule(s) dans calcChain.xml sans formule active : {', '.join(sorted(diff_chain))}")
            else:
                st.success("calcChain.xml est cohérent avec les formules actives.")

    with tabs[3]:
        section("Chemin local de sauvegarde (x15ac:absPath)", "Recherche un chemin absolu enregistré.")
        abs_match = re.search(r'x15ac:absPath\s+url="([^"]+)"', workbook_xml)
        if abs_match: st.warning(f"Chemin local enregistré : **{abs_match.group(1)}**")

        section("Feuilles cachées / très cachées", "veryHidden indique une feuille masquée non révélable directement.")
        hidden_sheets = re.findall(r'<sheet\b[^>]*name="([^"]+)"[^>]*state="([^"]+)"', workbook_xml)
        if hidden_sheets:
            st.warning(f"{len(hidden_sheets)} feuille(s) cachée(s) :")
            for name, state in hidden_sheets: st.write(f"- **{name}** ({state})")
        else: st.success("Aucune feuille cachée détectée.")

        if "xl/sharedStrings.xml" in names:
            shared_xml = safe_zip_read(zf, "xl/sharedStrings.xml") or ""
            strings = re.findall(r"<t[^>]*>(.*?)</t>", shared_xml, re.DOTALL)
            st.metric(t("Chaînes uniques (sharedStrings)", "Unique Strings (sharedStrings)"), len(strings))

    with tabs[4]:
        rev_files = [n for n in names if n.startswith("xl/revisions/")]
        st.write(f"{len(rev_files)} {t('fichier(s) de révision trouvé(s).', 'revision file(s) found.')}")
        for rf in rev_files[:10]:
            content = safe_zip_read(zf, rf)
            if content:
                revision_authors = set(re.findall(r'userName="([^"]+)"', content))
                if revision_authors: st.warning(f"{rf} : {t('auteurs', 'authors')} = {', '.join(sorted(revision_authors))}")
                with st.expander(f"Voir {rf}"): st.code(content[:3000], language="xml")

    with tabs[5]:
        section(
            t("Séquence Chronologique des Textes (sharedStrings.xml)", "Chronological Text Sequence (sharedStrings.xml)"),
            t("Analyse l'ordre d'introduction des chaînes de caractères (sharedStrings) et met en évidence les textes orphelins (supprimés ou modifiés).", "Analyzes the entry order of character strings (sharedStrings) and highlights orphaned (deleted or modified) texts.")
        )
        if "xl/sharedStrings.xml" in names:
            shared_xml = safe_zip_read(zf, "xl/sharedStrings.xml") or ""
            shared_strings = []
            si_blocks = re.findall(r'<si\b[^>]*>(.*?)</si>', shared_xml, re.DOTALL)
            for sib in si_blocks:
                t_vals = re.findall(r'<t\b[^>]*>(.*?)</t>', sib, re.DOTALL)
                shared_strings.append("".join(t_vals))
            
            referenced_indices = set()
            worksheet_files = [name for name in names if name.startswith("xl/worksheets/") and name.endswith(".xml")]
            for wf in worksheet_files:
                sheet_xml = safe_zip_read(zf, wf) or ""
                for cell_match in re.finditer(r'<c\b[^>]+t="s"[^>]*>.*?<v>(\d+)</v>', sheet_xml, re.DOTALL):
                    referenced_indices.add(int(cell_match.group(1)))
            
            total_strings = len(shared_strings)
            orphaned_strings = [i for i in range(total_strings) if i not in referenced_indices]
            
            col1, col2 = st.columns(2)
            with col1:
                st.metric(t("Total des chaînes", "Total Strings"), total_strings)
            with col2:
                st.metric(t("Chaînes orphelines (supprimées)", "Orphaned Strings (deleted)"), len(orphaned_strings))
            
            if total_strings > 0:
                rows = [[t("Index", "Index"), t("Statut", "Status"), t("Contenu Textuel", "Text Content")]]
                for i, s in enumerate(shared_strings):
                    status_text = t("✅ Actif", "✅ Active") if i in referenced_indices else t("⚠️ Orphelin (Supprimé)", "⚠️ Orphaned (Deleted)")
                    rows.append([str(i), status_text, s])
                
                st.markdown(t("### 📋 Historique d'apparition des textes (ordre chronologique)", "### 📋 Text Entry History (Chronological Order)"))
                limit = 200
                st.table(rows[:limit + 1])
                if total_strings > limit:
                    st.info(f"... {t('affichage limité aux', 'display limited to')} {limit} {t('premières chaînes sur', 'first strings out of')} {total_strings} ...")
        else:
            st.info(t("Aucun fichier sharedStrings.xml trouvé dans ce classeur.", "No sharedStrings.xml file found in this workbook."))



# ----------------------------------------------------------------------------
# Enhanced OLE & PDF Forensic Engines (oletools by decalage2 & PDF Tools by Didier Stevens)
# ----------------------------------------------------------------------------

def run_oletimes_safe(path: str) -> str:
    """Executes oletimes to extract internal OLE stream creation & modification timestamps."""
    return run_cmd(["oletimes", path], timeout=60)

def run_msodde_safe(path: str) -> str:
    """Executes msodde to detect DDE / DDEAUTO command execution fields."""
    return run_cmd(["msodde", path], timeout=60)

def run_oleobj_quarantine(path: str) -> list:
    """Executes oleobj to extract embedded OLE payloads into quarantine objects."""
    results = []
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            out = run_cmd(["oleobj", "-d", tmpdir, path], timeout=60)
            if os.path.exists(tmpdir):
                for fname in os.listdir(tmpdir):
                    fpath = os.path.join(tmpdir, fname)
                    if os.path.isfile(fpath):
                        fbytes = Path(fpath).read_bytes()
                        sha256 = hashlib.sha256(fbytes).hexdigest()
                        results.append({
                            "filename": fname,
                            "bytes": fbytes,
                            "size": len(fbytes),
                            "sha256": sha256
                        })
    except Exception:
        pass
    return results

def check_pdfid_name_mangling(pdfid_out: str) -> bool:
    """Checks if PDFiD output contains hex-escaped obfuscated keywords (Name Mangling evasion)."""
    if not pdfid_out or not isinstance(pdfid_out, str):
        return False
    mangling_pattern = r'/(?:J#|O#|A#|E#|L#|F#|X#)[a-zA-Z0-9#]+'
    return bool(re.search(mangling_pattern, pdfid_out, re.IGNORECASE))

def extract_pdf_javascript_streams(raw_bytes: bytes, path: str) -> list:
    """Extracts raw JavaScript stream content from PDF using decompressed FlateDecode streams or pdf-parser."""
    extracted_js = []
    if not raw_bytes:
        return extracted_js
    
    try:
        stream_matches = re.finditer(rb'/Length\s+(\d+).*?stream\r?\n(.*?)\r?\nendstream', raw_bytes, re.DOTALL)
        for match in stream_matches:
            stream_data = match.group(2)
            try:
                decompressed = zlib.decompress(stream_data)
                text_dec = decompressed.decode('utf-8', errors='ignore')
                if any(kw in text_dec for kw in ['eval(', 'app.launchURL', 'this.exportDataObject', 'util.printf', 'Collab.getIcon', 'SOAP.connect']):
                    extracted_js.append(text_dec[:10000])
            except Exception:
                pass
    except Exception:
        pass
    
    if not extracted_js:
        parser_out = run_cmd(["python", "tools/pdf-parser.py", "-s", "JavaScript", "-c", path], timeout=30)
        if parser_out and "stream" in parser_out.lower() and not parser_out.startswith("[Erreur"):
            extracted_js.append(parser_out[:10000])
            
    return extracted_js

def extract_pdf_embedded_files(raw_bytes: bytes, path: str) -> list:
    """Extracts embedded files from PDF /EmbeddedFiles objects into quarantine payload objects."""
    embedded_payloads = []
    if not raw_bytes:
        return embedded_payloads
    
    try:
        file_matches = re.finditer(r'/F\s*\(([^)]+)\).*?/EF\s*<<.*?/F\s+(\d+)\s+(\d+)\s+R', raw_bytes, re.DOTALL)
        for fm in file_matches:
            fname = fm.group(1)
            stream_match = re.search(rb'/Length\s+\d+.*?stream\r?\n(.*?)\r?\nendstream', raw_bytes, re.DOTALL)
            if stream_match:
                try:
                    payload_bytes = zlib.decompress(stream_match.group(1))
                    sha256 = hashlib.sha256(payload_bytes).hexdigest()
                    embedded_payloads.append({
                        "filename": fname,
                        "bytes": payload_bytes,
                        "size": len(payload_bytes),
                        "sha256": sha256
                    })
                except Exception:
                    pass
    except Exception:
        pass
    return embedded_payloads

def analyze_legacy_ole(path: str, is_excel: bool, collector: "ReportCollector" = None, risk_engine: ForensicRiskEngine = None, timeline: ForensicTimelineEngine = None):
    st.header(f"Analyse {'Excel' if is_excel else 'Word'} legacy (OLE)")
    tabs = st.tabs(["📊 Diagnostic OLE (oleid & olevba)", "⏱️ Horodatages des Flux (oletimes)", "⚠️ Injections DDE / Commandes (msodde)", "📦 Payloads & Quarantaine (oleobj)"])
    
    with tabs[0]:
        section("oleid", "Diagnostic OLE.")
        oleid_out = run_cmd(["oleid", path], timeout=60)
        st.code(oleid_out, language="text")
        section("olevba", "Code VBA.")
        olevba_out = run_cmd(["olevba", path], timeout=60)
        st.code(olevba_out, language="text")

    with tabs[1]:
        section("oletimes", "Horodatages internes des flux et dossiers OLE (anti-timestomping).")
        oletimes_out = run_oletimes_safe(path)
        st.code(oletimes_out, language="text")

    with tabs[2]:
        section("msodde", "Détection des injections de commandes DDE / DDEAUTO.")
        msodde_out = run_msodde_safe(path)
        if msodde_out and ("DDE" in msodde_out or "cmd.exe" in msodde_out.lower() or "powershell" in msodde_out.lower()):
            st.error("🚨 ALERTE INJECTION DDE / DDEAUTO : Des champs d'exécution de commandes système ont été détectés !")
            st.code(msodde_out, language="text")
            if risk_engine:
                risk_engine.add_finding("Injection DDE / DDEAUTO", "Commande système DDE/DDEAUTO détectée dans les champs de texte", 30, "HAUT", "champs OLE / msodde")
        else:
            st.success("Aucune injection de commande DDE/DDEAUTO détectée.")
            st.code(msodde_out, language="text")

    with tabs[3]:
        section("oleobj", "Extraction et quarantaine des payloads OLE embarqués (Ole10Native / Packager).")
        payloads = run_oleobj_quarantine(path)
        if payloads:
            st.warning(f"⚠️ {len(payloads)} payload(s) binaire(s) OLE extrait(s) du document !")
            if risk_engine:
                risk_engine.add_finding("Payload OLE Native (Ole10Native)", f"{len(payloads)} objet(s) binaire(s) OLE embarqué(s) trouvé(s)", 25, "HAUT", "oleobj / Packager")
            for p in payloads:
                c1, c2 = st.columns([3, 1])
                with c1:
                    st.code(f"Nom : {p['filename']} ({p['size']} octets) — SHA-256: {p['sha256']}")
                with c2:
                    st.download_button(
                        f"Télécharger {p['filename']} (Quarantaine)",
                        data=p['bytes'],
                        file_name=f"quarantaine_{p['filename']}",
                        mime="application/octet-stream",
                        key=f"oleobj_dl_{p['sha256'][:10]}"
                    )
        else:
            st.success("Aucun payload binaire OLE embarqué résiduel dans le document.")



def decode_thread_index(thread_index_b64: str):
    try:
        raw = base64.b64decode(thread_index_b64)
        if len(raw) < 22:
            return None
        filetime_bytes = raw[:6] + b"\x00\x00"
        filetime = struct.unpack("<Q", filetime_bytes)[0]
        EPOCH_AS_FILETIME = 116444736000000000
        HUNDREDS_OF_NANOSECONDS = 10000000
        unix_timestamp = (filetime - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS
        return datetime.fromtimestamp(unix_timestamp, tz=timezone.utc)
    except Exception:
        return None


def analyze_eml(raw: bytes, collector: "ReportCollector" = None, risk_engine: ForensicRiskEngine = None, timeline: ForensicTimelineEngine = None):
    st.header("Analyse EML")
    try: msg = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as e: st.error(f"Impossible de parser le message : {e}"); return

    tabs = st.tabs(["📊 Risk & Timeline", "📧 En-têtes & Relais", "💬 Corps & Divergence HTML/Texte", "📎 Pièces jointes & URLs"])

    with tabs[0]:
        date_hdr = msg.get(t("Date", "Date"))
        if date_hdr and timeline: timeline.add_event(str(date_hdr), "EML Header Date", "Email Date", "Date déclarée EML")
        risk_engine.render_risk_badge()
        timeline.render_timeline(collector, risk_engine)

    with tabs[1]:
        section("En-têtes principaux", "Expéditeur, destinataires, sujet et dates déclarées.")
        for h in ["From", "To", "Cc", "Subject", t("Date", "Date"), "Message-ID", "Return-Path"]:
            if msg.get(h): st.write(f"**{h}** : {msg.get(h)}")

        section("Chaîne des serveurs relais (Received)", "Chaque en-tête Received représente un saut de serveur.")
        received_headers = msg.get_all("Received") or []
        st.write(f"{len(received_headers)} en-tête(s) Received trouvé(s).")
        if received_headers:
            with st.expander("Voir la chaîne de relais complète"):
                for i, r in enumerate(received_headers):
                    st.code(f"[{i + 1}] {r}", language="text")

        section("Authentification (SPF / DKIM / DMARC)", "Vérifie les résultats d'authentification.")
        auth_results = msg.get_all("Authentication-Results") or []
        if auth_results:
            for ar in auth_results:
                st.code(ar, language="text")
                for mech in ("spf", "dkim", "dmarc"):
                    m = re.search(rf"{mech}=(\w+)", ar, re.IGNORECASE)
                    if m and m.group(1).lower() not in ("pass",):
                        st.warning(f"Résultat {mech.upper()} non conforme : **{m.group(1)}**")
        else:
            st.caption("Aucun en-tête Authentication-Results trouvé.")

        section("Thread-Index (Outlook)", "Décode l'horodatage embarqué dans l'en-tête Thread-Index.")
        thread_index = msg.get("Thread-Index")
        if thread_index:
            decoded = decode_thread_index(str(thread_index))
            if decoded:
                st.info(f"Horodatage original décode depuis Thread-Index : **{decoded.isoformat()}**")
                if timeline: timeline.add_event(decoded.isoformat(), "Outlook Thread-Index", "Thread Date", "Date issue de l'en-tête Thread-Index Outlook")
            else:
                st.caption("Thread-Index présent mais non décodable.")
        else:
            st.caption("Aucun en-tête Thread-Index trouvé.")

    with tabs[2]:
        text_content, html_content = "", ""
        for part in msg.walk():
            if part.get_content_disposition() == "attachment": continue
            if part.get_content_type() == "text/plain" and not text_content:
                text_content = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="replace")
            elif part.get_content_type() == "text/html" and not html_content:
                html_content = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="replace")

        if text_content and html_content:
            clean_html = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html_content)).strip()
            clean_text = re.sub(r"\s+", " ", text_content).strip()
            diff_len = abs(len(clean_text) - len(clean_html))
            if diff_len > 150:
                st.warning(f"**Divergence importante ({diff_len} caractères)** entre la version Texte et HTML.")
                risk_engine.add_risk(25, "HAUT", "Phishing EML", f"Écart de {diff_len} caractères entre Texte et HTML !")

    with tabs[3]:
        extract_urls_and_payloads(raw, risk_engine=risk_engine)


def analyze_msg(raw: bytes, collector: "ReportCollector" = None, risk_engine: ForensicRiskEngine = None, timeline: ForensicTimelineEngine = None):
    st.header("Analyse Outlook MSG (Format OLE Compound File)")
    
    msg_obj = None
    try:
        import extract_msg
        msg_obj = extract_msg.Message(io.BytesIO(raw))
    except Exception as e:
        st.error(f"Impossible de parser le fichier MSG : {e}")
        return

    tabs = st.tabs(["📊 Risk & Timeline", "📧 Métadonnées & En-têtes Outlook", "💬 Corps & Divergence HTML/Texte", "📎 Pièces jointes & Payloads"])

    with tabs[0]:
        date_hdr = getattr(msg_obj, 'date', None)
        if date_hdr and timeline:
            timeline.add_event(str(date_hdr), "MSG Header Date", "Email Date", "Date déclarée dans le message Outlook MSG")
        risk_engine.render_risk_badge()
        timeline.render_timeline(collector, risk_engine)

    with tabs[1]:
        section("Métadonnées Outlook MSG", "Expéditeur, destinataires, sujet et classe de message.")
        st.write(f"**De (Sender)** : {getattr(msg_obj, 'sender', 'Non spécifié')}")
        st.write(f"**À (To)** : {getattr(msg_obj, 'to', 'Non spécifié')}")
        st.write(f"**CC** : {getattr(msg_obj, 'cc', 'Non spécifié')}")
        st.write(f"**Sujet (Subject)** : {getattr(msg_obj, 'subject', 'Non spécifié')}")
        st.write(f"**Date** : {getattr(msg_obj, 'date', 'Non spécifiée')}")
        st.write(f"**Message-ID** : {getattr(msg_obj, 'messageId', 'Non spécifié')}")
        st.write(f"**Class Message** : {getattr(msg_obj, 'messageClass', 'IPM.Note')}")

        headers_str = str(getattr(msg_obj, 'header', '') or '')
        if headers_str:
            with st.expander("Voir les en-têtes réseau bruts (Internet Headers)"):
                st.code(headers_str, language="text")
                
            for mech in ("spf", "dkim", "dmarc"):
                m = re.search(rf"{mech}=(\w+)", headers_str, re.IGNORECASE)
                if m and m.group(1).lower() not in ("pass",):
                    st.warning(f"Résultat {mech.upper()} non conforme : **{m.group(1)}**")

    with tabs[2]:
        text_body = str(getattr(msg_obj, 'body', '') or '')
        html_body = str(getattr(msg_obj, 'htmlBody', '') or '')
        
        st.subheader("Corps du message (Texte brut)")
        if text_body:
            st.text_area("Texte principal", text_body, height=200)
        else:
            st.caption("Aucun corps texte brut disponible.")
            
        if html_body:
            st.subheader("Corps HTML")
            with st.expander("Voir le code source HTML du message"):
                st.code(html_body, language="html")

        if text_body and html_body:
            clean_html = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html_body)).strip()
            clean_text = re.sub(r"\s+", " ", text_body).strip()
            diff_len = abs(len(clean_text) - len(clean_html))
            if diff_len > 150:
                st.warning(f"**Divergence importante ({diff_len} caractères)** entre la version Texte et HTML.")
                risk_engine.add_risk(25, "HAUT", "Phishing MSG", f"Écart de {diff_len} caractères entre Texte et HTML !", source_location="MSG Body -> Divergence Texte/HTML")

    with tabs[3]:
        section("Pièces jointes embarquées dans le MSG", "Extraction et quarantaine des pièces jointes.")
        attachments = getattr(msg_obj, 'attachments', []) or []
        if attachments:
            st.error(f"{len(attachments)} pièce(s) jointe(s) trouvée(s) dans le message MSG !")
            for att in attachments:
                att_name = getattr(att, 'longFilename', None) or getattr(att, 'shortFilename', None) or "piece_jointe.bin"
                att_data = getattr(att, 'data', b"")
                if att_data:
                    b_hash = sha256_of(att_data)
                    btn_key = f"msg_att_{sha256_of(att_name.encode())[:12]}"
                    st.code(f"{att_name} ({len(att_data)} octets) — SHA-256: {b_hash}", language="text")
                    st.download_button(
                        f"Télécharger {att_name} (Quarantaine)",
                        data=att_data,
                        file_name=f"quarantaine_{att_name}",
                        key=btn_key
                    )
                    ext_att = Path(att_name).suffix.lower()
                    if ext_att in DANGEROUS_PAYLOAD_EXTS:
                        risk_engine.add_risk(30, t("CRITIQUE", "CRITICAL"), "Payload MSG", f"Pièce jointe à haut risque : {att_name}", source_location=f"Fichier MSG -> Pièce jointe '{att_name}'")
        else:
            st.success("Aucune pièce jointe dans ce fichier MSG.")
            
        extract_urls_and_payloads(raw, risk_engine=risk_engine)


# ----------------------------------------------------------------------------
# 10. Module Multi-Fichiers / Analyse de Campagne (Corrélation)
# ----------------------------------------------------------------------------

def render_campaign_multi_file_analysis():
    st.header("👥 Analyse Multi-Fichiers / Corrélation de Campagne")
    explain("Dépose 2 à 10 fichiers simultanément pour générer une matrice de corrélation croisée.")
    
    files = st.file_uploader(
        "Dépose plusieurs fichiers à comparer (PDF, DOCX, XLSX, EML)",
        type=["pdf", "docx", "xlsx", "docm", "xlsm", "eml"],
        accept_multiple_files=True,
        key="campaign_uploader"
    )

    if not files or len(files) < 2:
        st.info("Sélectionne au moins 2 fichiers pour lancer la corrélation croisée.")
        return

    st.success(f"{len(files)} fichiers chargés pour analyse de campagne.")
    
    campaign_data = []
    for f in files:
        f_raw = f.read()
        f_hash = sha256_of(f_raw)
        
        info = {
            "name": f.name,
            "hash": f_hash,
            "type": Path(f.name).suffix.lower(),
            "authors": set(),
            "rsids": set(),
            "doc_id": None,
            "urls": set()
        }

        try:
            zf = zipfile.ZipFile(io.BytesIO(f_raw))
            names = zf.namelist()
            if "docProps/core.xml" in names:
                core = safe_zip_read(zf, "docProps/core.xml") or ""
                cr = re.search(r"<dc:creator>(.*?)</dc:creator>", core)
                mo = re.search(r"<cp:lastModifiedBy>(.*?)</cp:lastModifiedBy>", core)
                if cr: info["authors"].add(cr.group(1))
                if mo: info["authors"].add(mo.group(1))
            if "word/document.xml" in names:
                doc_xml = safe_zip_read(zf, "word/document.xml") or ""
                info["rsids"] = {seg["rsid"] for para in parse_docx_paragraphs_with_rsid(doc_xml) for seg in para if seg["rsid"]}
            if "word/settings.xml" in names:
                settings_xml = safe_zip_read(zf, "word/settings.xml") or ""
                docid_match = re.search(r'w1[45]:docId\s+w1[45]:val="(\{[0-9A-Fa-f\-]+\})"', settings_xml)
                if docid_match: info["doc_id"] = docid_match.group(1)
        except Exception:
            pass

        campaign_data.append(info)

    st.subheader("Matrice de Corrélation Croisée")
    
    all_authors = {}
    for item in campaign_data:
        for a in item["authors"]:
            all_authors.setdefault(a, []).append(item["name"])
            
    shared_authors = {a: files for a, files in all_authors.items() if len(files) > 1}
    if shared_authors:
        st.warning("Auteurs partagés entre plusieurs documents :")
        for a, flist in shared_authors.items():
            st.write(f"• **{a}** présent dans : {', '.join(flist)}")
    else:
        st.caption("Aucun nom d'auteur partagé en commun.")

    all_rsids = {}
    for item in campaign_data:
        for r in item["rsids"]:
            all_rsids.setdefault(r, []).append(item["name"])
            
    shared_rsids = {r: files for r, files in all_rsids.items() if len(files) > 1}
    if shared_rsids:
        st.error(f"{len(shared_rsids)} RSID(s) partagé(s) entre plusieurs documents DOCX :")
        for r, flist in shared_rsids.items():
            st.write(f"• RSID **{r}** présent dans : {', '.join(flist)}")
    else:
        st.caption("Aucun session RSID commune entre les fichiers DOCX.")

    table_rows = [["Fichier", "Hash SHA-256", "Auteurs", "docId", "Nb RSID"]]
    for item in campaign_data:
        table_rows.append([
            item["name"],
            item["hash"],
            ", ".join(item["authors"]) if item["authors"] else "N/A",
            item["doc_id"] or "N/A",
            str(len(item["rsids"]))
        ])
    st.table(table_rows)


def extract_metadata_summary(raw: bytes, ext: str, path: str = "") -> dict:
    meta = {
        "creator": "Non spécifié",
        "last_modified_by": "Non spécifié",
        "company": "Non spécifiée",
        "revision": "Non spécifiée",
        "total_edit_time": "Non spécifié",
        "doc_id": "Non spécifié",
        "application": "Non spécifiée",
        "tools_detected": []
    }
    
    raw_str = raw[:2000000].decode("latin1", errors="ignore")
    for item in KNOWN_CONVERTERS_PATTERNS:
        if re.search(item["pattern"], raw_str, re.IGNORECASE):
            meta["tools_detected"].append(item["name"])

    if ext in (".docx", ".docm", ".xlsx", ".xlsm"):
        try:
            zf = zipfile.ZipFile(io.BytesIO(raw))
            names = zf.namelist()
            if "docProps/core.xml" in names:
                core_xml = safe_zip_read(zf, "docProps/core.xml") or ""
                root = parse_xml_bytes(core_xml.encode("utf-8", errors="ignore"))
                if root is not None:
                    creators = [e.text for e in findall_local(root, "creator") if e.text]
                    modifiers = [e.text for e in findall_local(root, "lastModifiedBy") if e.text]
                    revisions = [e.text for e in findall_local(root, "revision") if e.text]
                    if creators: meta["creator"] = creators[0].strip()
                    if modifiers: meta["last_modified_by"] = modifiers[0].strip()
                    if revisions: meta["revision"] = revisions[0].strip()
                
                # Repli regex si ElementTree n'a pas capturé
                if meta["creator"] == "Non spécifié":
                    cr = re.search(r"<dc:creator[^>]*>(.*?)</dc:creator>", core_xml, re.DOTALL)
                    if cr and cr.group(1).strip(): meta["creator"] = cr.group(1).strip()
                if meta["last_modified_by"] == "Non spécifié":
                    mo = re.search(r"<cp:lastModifiedBy[^>]*>(.*?)</cp:lastModifiedBy>", core_xml, re.DOTALL)
                    if mo and mo.group(1).strip(): meta["last_modified_by"] = mo.group(1).strip()

            if "docProps/app.xml" in names:
                app_xml = safe_zip_read(zf, "docProps/app.xml") or ""
                root_app = parse_xml_bytes(app_xml.encode("utf-8", errors="ignore"))
                if root_app is not None:
                    comps = [e.text for e in findall_local(root_app, "Company") if e.text]
                    apps = [e.text for e in findall_local(root_app, "Application") if e.text]
                    tts = [e.text for e in findall_local(root_app, "TotalTime") if e.text and e.text.isdigit()]
                    if comps: meta["company"] = comps[0].strip()
                    if apps: meta["application"] = apps[0].strip()
                    if tts:
                        mins = int(tts[0])
                        meta["total_edit_time"] = f"{mins // 60}h{mins % 60:02d}min ({mins} min)"

            if "word/settings.xml" in names:
                settings_xml = safe_zip_read(zf, "word/settings.xml") or ""
                docid_match = re.search(r'w1[45]:docId\s+w1[45]:val="(\{[0-9A-Fa-f\-]+\})"', settings_xml)
                if docid_match: meta["doc_id"] = docid_match.group(1)
        except Exception:
            pass

    elif ext == ".pdf":
        exiftool_out = run_cmd(["exiftool", "-G1", "-a", "-s", path], timeout=15) or ""
        if not exiftool_out or "Could not find" in exiftool_out or "[OUTIL NON TROUVÉ" in exiftool_out:
            exiftool_out = get_pdf_metadata_fallback(raw)
        for line in exiftool_out.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                k_lower = k.strip().lower()
                val = v.strip()
                if "author" in k_lower:
                    if val and meta["creator"] == "Non spécifié":
                        meta["creator"] = val
                elif "lastmodifiedby" in k_lower or "modby" in k_lower:
                    if val and meta["last_modified_by"] == "Non spécifié":
                        meta["last_modified_by"] = val
                elif "producer" in k_lower or "creator" in k_lower:
                    if val and meta["application"] == "Non spécifiée":
                        meta["application"] = val

    return meta


def pre_scan_document(path: str, raw: bytes, ext: str, risk_engine: ForensicRiskEngine, timeline: ForensicTimelineEngine, collector: ReportCollector = None):
    meta_summary = extract_metadata_summary(raw, ext, path)
    if collector is not None:
        collector.add("metadata_summary", meta_summary)
        
    cr = meta_summary.get("creator")
    mo = meta_summary.get("last_modified_by")
    if is_valid_person_name(cr) and is_valid_person_name(mo) and cr != mo:
        risk_engine.add_risk(10, t("FAIBLE", "LOW"), "Auteur / Révision Tiers", f"Identités d'auteurs différentes : créé par '{cr}', modifié en dernier par '{mo}'", source_location="docProps/core.xml -> <dc:creator> & <cp:lastModifiedBy>")
        
    raw_str = raw[:2000000].decode("latin1", errors="ignore")
    
    if YARA_AVAILABLE:
        try:
            rule_str = """
            rule Office_VBA_Suspicious {
                strings:
                    $a = "WScript.Shell" ascii wide nocase
                    $b = "ShellExecute" ascii wide nocase
                    $c = "AutoOpen" ascii wide nocase
                    $d = "ms-msdt:" ascii wide nocase
                condition:
                    any of them
            }
            """
            compiled = yara.compile(source=rule_str)
            yara_res = compiled.match(data=raw)
            for m in yara_res:
                risk_engine.add_risk(25, "HAUT", "YARA", f"Matche YARA : {m.rule}", source_location="Analyse binaire YARA")
        except Exception:
            pass

    for r in BUILTIN_REGEX_RULES:
        if re.search(r["pattern"], raw_str, re.IGNORECASE):
            risk_engine.add_risk(r["risk"], r["severity"], "YARA/Signature", f"Règle [{r['name']}] : {r['desc']}", source_location=f"Scan binaire RAW -> Règle {r['name']}")

    combined_str = raw_str.lower()
    for item in KNOWN_CONVERTERS_PATTERNS:
        match_obj = re.search(item["pattern"], combined_str, re.IGNORECASE)
        if match_obj:
            matched_text = match_obj.group(0)
            if item["key"] in ("smallpdf", "ilovepdf", "pdf2go"):
                risk_engine.add_risk(
                    15, "MOYEN", "Convertisseur Web",
                    f"Conversion via service web tiers : {item['name']}",
                    source_location=f"Scan binaire RAW -> Motif '{matched_text}'"
                )

    regex_url = r"(?:https?|ftp|file|ms-msdt|search-ms|mhtml)://[^\s\"'<>]+"
    urls_found = set(re.findall(regex_url, raw_str, re.IGNORECASE))
    for url in urls_found:
        if re.search(r"(?:127\.0\.0\.1|localhost|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", url):
            risk_engine.add_risk(25, "HAUT", "URL Suspecte", f"Adresse IP directe / Hôte brut : {url}", source_location="Composants XML / Liens réseau")
        elif any(proto in url.lower() for proto in ["ms-msdt:", "file://", "mhtml:", "search-ms:"]):
            risk_engine.add_risk(25, "HAUT", "URL Suspecte", f"Protocole réseau dangereux : {url}", source_location="Composants XML / Liens réseau")

    if ext in (".docx", ".docm", ".xlsx", ".xlsm"):
        try:
            zf = zipfile.ZipFile(io.BytesIO(raw))
            names = zf.namelist()
            for name in names:
                name_lower = name.lower()
                if "printersettings" in name_lower:
                    continue
                ext_n = Path(name_lower).suffix
                if "embeddings/" in name_lower or ext_n in DANGEROUS_PAYLOAD_EXTS:
                    risk_engine.add_risk(30, t("CRITIQUE", "CRITICAL"), "Payload OLE", f"Objet binaire embarqué : {name}", source_location=f"Archive ZIP -> {name}")

            content_types_xml = safe_zip_read(zf, "[Content_Types].xml") or ""
            override_files = set(re.findall(r'PartName="([^"]+)"', content_types_xml))
            default_extensions = set(e.lower() for e in re.findall(r'Extension="([^"]+)"', content_types_xml))
            default_extensions.update({
                "rels", "xml", "png", "jpeg", "jpg", "bin", "bmp", "emf", "wmf", "tif", "tiff", "txt",
                "svg", "webp", "eps", "gif", "ico", "mp4", "mp3", "wav", "dat", "css", "js", "html"
            })
            for n in names:
                if n in ("[Content_Types].xml", "_rels/.rels") or n.endswith(".rels") or "/_rels/" in n or n.startswith("customXml/"):
                    continue
                ext_n = Path(n).suffix.lstrip(".").lower()
                formatted_name = "/" + n if not n.startswith("/") else n
                if formatted_name not in override_files and ext_n not in default_extensions:
                    risk_engine.add_risk(25, "HAUT", "Stéganographie ZIP", f"Fichier masqué non référencé : {n}", source_location=f"Archive ZIP -> {n} (absent de [Content_Types].xml)")

            if "word/document.xml" in names:
                doc_xml = safe_zip_read(zf, "word/document.xml") or ""
                root = parse_xml_bytes(doc_xml.encode("utf-8", errors="ignore"))
                if root is not None:
                    for p_elem in findall_local(root, "p"):
                        for r_elem in findall_local(p_elem, "r"):
                            rPr = findall_local(r_elem, "rPr")
                            if rPr:
                                pr = rPr[0]
                                if findall_local(pr, "vanish") or findall_local(pr, "webHidden"):
                                    risk_engine.add_risk(15, "MOYEN", "Masquage Texte", "Attribut w:vanish sur du texte", source_location="word/document.xml -> <w:vanish>")
                                color_elems = findall_local(pr, "color")
                                if color_elems:
                                    c_val = get_attr_local(color_elems[0], "val")
                                    if c_val and c_val.upper() in ("FFFFFF", "AUTO"):
                                        shd_elems = findall_local(pr, "shd")
                                        shd_val = get_attr_local(shd_elems[0], "fill") if shd_elems else None
                                        if c_val.upper() == "FFFFFF" or (shd_val and shd_val.upper() == "FFFFFF"):
                                            risk_engine.add_risk(20, "HAUT", "Texte Camouflé", "Texte blanc sur fond blanc", source_location="word/document.xml -> <w:color w:val='FFFFFF'>")
                                sz_elems = findall_local(pr, "sz")
                                if sz_elems:
                                    sz_val = get_attr_local(sz_elems[0], "val")
                                    if sz_val and sz_val.isdigit() and int(sz_val) <= 4:
                                        risk_engine.add_risk(15, "MOYEN", "Micro-police", "Taille police < 2pt", source_location="word/document.xml -> <w:sz w:val='4'>")
                
                drawings = re.findall(r"<(?:v:rect|v:shape|w:drawing)\b[^>]*>", doc_xml)
                black_rects = [d for d in drawings if "fillcolor=\"black\"" in d.lower() or "#000000" in d.lower()]
                if black_rects:
                    risk_engine.add_risk(25, "HAUT", "Faux Caviardage", f"{len(black_rects)} formes noires superposées sur du texte XML non effacé !", source_location="word/document.xml -> <v:rect fillcolor='black'>")

                declared_rsids = set(re.findall(r'w:rsid w:val="([0-9A-Fa-f]+)"', safe_zip_read(zf, "word/settings.xml") or ""))
                mapping = analyze_rsid_mapping(doc_xml, declared_rsids)
                if mapping["orphan_rsids"]:
                    risk_engine.add_risk(15, "MOYEN", "RSID Orphelin", f"{len(mapping['orphan_rsids'])} RSID non déclaré(s) dans settings.xml (Texte copié-collé depuis un document externe ou script)", source_location="word/document.xml -> Attribut w:rsidR (absent de word/settings.xml)")

            for rel_name in [n for n in names if n.endswith("settings.xml.rels") or n.endswith("webSettings.xml.rels")]:
                content = safe_zip_read(zf, rel_name)
                if content:
                    matches = re.findall(r'Type="[^"]*attachedTemplate"[^>]*Target="([^"]+)"', content)
                    for m in matches:
                        if m.startswith("\\\\") or m.startswith("http://") or m.startswith("https://"):
                            risk_engine.add_risk(30, t("CRITIQUE", "CRITICAL"), "Modèle Distant", f"attachedTemplate UNC/Web : {m}", source_location=f"{rel_name} -> Target='{m}'")

            if "word/vbaProject.bin" in names:
                risk_engine.add_risk(25, "HAUT", "Macro VBA", "Fichier vbaProject.bin présent dans DOCM", source_location="Archive ZIP -> word/vbaProject.bin")
        except Exception:
            pass

    if ext == ".pdf":
        eof_count = raw.count(b"%%EOF")
        if eof_count > 1:
            risk_engine.add_risk(15, "MOYEN", "PDF Incrémental", f"{eof_count} révisions incrémentales trouvées dans le PDF", source_location="Structure binaire PDF -> Marqueurs %%EOF")


# ----------------------------------------------------------------------------
# Point d'entree principal
# ----------------------------------------------------------------------------

render_dependency_check()

app_mode = st.sidebar.radio(t("Mode d'analyse", "Analysis Mode"), [t("📄 Document Unique", "📄 Single Document"), t("👥 Campagne Multi-Fichiers", "👥 Multi-File Campaign")])

if app_mode == t("👥 Campagne Multi-Fichiers", "👥 Multi-File Campaign"):
    render_campaign_multi_file_analysis()
else:
    input_method = st.radio(
        t("Méthode d'entrée du fichier", "File Input Method"),
        [t("📤 Glisser-Déposer / Téléversement Navigateur", "📤 Drag & Drop / Browser Upload"), t("📂 Chemin d'accès Local Direct (Conserve les dates système FileModifyDate d'origine)", "📂 Direct Local Path (Preserves original FileModifyDate)")],
        horizontal=True
    )

    target_path = None
    raw = None
    filename = ""
    is_temp = False

    if input_method == t("📤 Glisser-Déposer / Téléversement Navigateur", "📤 Drag & Drop / Browser Upload"):
        uploaded = st.file_uploader(
            t("Dépose un fichier PDF, DOCX, XLSX, DOC, XLS, EML ou MSG", "Drop a PDF, DOCX, XLSX, DOC, XLS, EML, or MSG file"),
            type=["pdf", "docx", "xlsx", "docm", "xlsm", "doc", "xls", "eml", "msg"]
        )
        if uploaded is not None:
            raw = uploaded.read()
            filename = uploaded.name
            with tempfile.NamedTemporaryFile(delete=False, suffix=Path(filename).suffix) as tmp:
                tmp.write(raw)
                target_path = tmp.name
            is_temp = True
            st.info(t("ℹ️ **Mode Téléversement Navigateur** : Le fichier temporaire créé sur le disque porte l'heure de l'analyse. Pour analyser un fichier local en conservant ses vraies dates système disque `FileModifyDate`, utilisez l'option 'Chemin d'accès Local Direct'.", "ℹ️ **Browser Upload Mode**: The temp file created on disk bears the analysis time. To preserve real dates, use the 'Direct Local Path' option."))
    else:
        local_path_str = st.text_input(t("Saisis ou colle le chemin d'accès absolu du fichier local", "Enter or paste the absolute path of the local file"), placeholder=r"C:\Chemin\Vers\Contrat.pdf")
        if local_path_str:
            clean_path = local_path_str.strip('\'"')
            if os.path.exists(clean_path) and os.path.isfile(clean_path):
                target_path = clean_path
                filename = os.path.basename(clean_path)
                with open(target_path, "rb") as f:
                    raw = f.read()
                is_temp = False
                st.success(f"📌 **Analyse directe sur disque** : `{target_path}` (Dates système `FileModifyDate` & `FileCreateDate` d'origine préservées à 100% !)")
            else:
                st.error("Fichier local introuvable ou chemin d'accès invalide.")

    if target_path and raw and filename:
        file_hash = sha256_of(raw)
        st.write(f"Fichier : **{filename}** | SHA-256 : `{file_hash}`")

        collector = ReportCollector(filename, file_hash)
        risk_engine = ForensicRiskEngine()
        timeline = ForensicTimelineEngine()

        # Si analyse directe sur disque, ajouter la vraie date de modification système du disque à la Timeline !
        if not is_temp:
            try:
                mtime = os.path.getmtime(target_path)
                mtime_dt = datetime.fromtimestamp(mtime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                timeline.add_event(mtime_dt, "Disque Local (File System)", "FileModifyDate", f"Date de modification système d'origine sur le disque (`{mtime_dt}`)")
            except Exception:
                pass

        try:
            ext = Path(filename).suffix.lower()
            pre_scan_document(target_path, raw, ext, risk_engine, timeline, collector)
            
            if ext == ".pdf":
                analyze_pdf(target_path, raw, collector, risk_engine, timeline)
            elif ext in (".docx", ".docm"):
                analyze_word_modern(target_path, raw, collector, risk_engine, timeline)
            elif ext in (".xlsx", ".xlsm"):
                analyze_excel_modern(target_path, raw, collector, risk_engine, timeline)
            elif ext in (".doc", ".xls"):
                analyze_legacy_ole(target_path, is_excel=(ext == ".xls"), collector=collector)
            elif ext == ".eml":
                analyze_eml(raw, collector, risk_engine, timeline)
            elif ext == ".msg":
                analyze_msg(raw, collector, risk_engine, timeline)
            else:
                st.error("Extension non prise en charge.")
        finally:
            if is_temp and os.path.exists(target_path):
                try:
                    os.unlink(target_path)
                except OSError:
                    pass

        render_report_export(collector, filename, file_hash, risk_engine, timeline)
