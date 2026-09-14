# Forensic Doc Analyzer v1.0.0

**Forensic Doc Analyzer** is a local, offline application designed for exploring and triaging digital documents. It extracts metadata, detects macros, OLE objects, DDE injections, and template links, analyzes image error levels (ELA), extracts PDF streams and embedded files into quarantine, and parses MS Outlook (.msg/.eml) email files.

Developed by **Dam-FOR3K (with the help of Antigravity AI)**.

---

## ⚠️ Methodological Forensic Disclaimer

> **IMPORTANT :**  
> This software is an **experimental exploration and triage assistant**. In digital forensics, **no automated output should be accepted as definitive evidence without manual corroboration**.  
> Forensic examiners must independently verify all extracted events, timestamps, and anomalies by directly inspecting the primary source containers (raw zip segments, XML nodes, PDF object structures, OLE streams) using independent hex editors and reference utilities.

---

## Features

- **Multi-Format Support**: PDF, DOCX, XLSX, DOCM, XLSM, DOC, XLS, EML, MSG.
- **100% Offline / Air-Gapped**: Runs entirely locally without any internet connection. Includes fallback Pure-Python parsers.
- **Forensic Timeline**: Tracks file timestamps, preventing OS filesystem pollution.
- **OLE Internal Timestamps (`oletimes`)**: Compares internal OLE stream creation/modification dates against disk timestamps to detect Timestomping.
- **DDE & DDEAUTO Injection Detection (`msodde`)**: Detects macro-less command execution fields in Word/Excel/OLE documents.
- **OLE & PDF Payload Quarantine (`oleobj` / `pdf-parser`)**: Extracts embedded binary packages (Ole10Native) and PDF embedded files, computes SHA-256 fingerprints, and provides download buttons for quarantine analysis.
- **PDF Obfuscation & Name Mangling (`pdfid`)**: Identifies hex-escaped keyword evasion techniques (`/J#61vaScript`) and decompresses FlateDecode JavaScript streams.
- **Bilingual UI**: Switch seamlessly between French and English.
- **Direct Disk Analysis**: Analyze files via direct local paths to preserve exact disk 'FileModifyDate' timestamps.
- **Malware & Phishing Detection**: Detects remote UNC templates, obfuscated VBA macros, and HTML vs Plain-Text divergence in emails.

---

## 📜 Credits & Open-Source Forensic Authors

This project builds upon and integrates ideas, algorithms, and utilities from leading figures in the digital forensics & malware analysis community:

- **Philippe Lagadec / decalage2 (`oletools`)**  
  *French Cybersecurity Expert & Author of `oletools` (`olevba`, `oleid`, `oletimes`, `oleobj`, `msodde`, `rtfobj`).*  
  Website: [decalage.info](https://www.decalage.info) | GitHub: [github.com/decalage2/oletools](https://github.com/decalage2/oletools)

- **Didier Stevens (PDF Tools / DidierStevensSuite)**  
  *Belgian Senior Information Security Consultant (NVISO) & Creator of industry-standard PDF forensic utilities (`pdfid.py`, `pdf-parser.py`).*  
  Website: [blog.didierstevens.com](https://blog.didierstevens.com) | GitHub: [github.com/DidierStevens/DidierStevensSuite](https://github.com/DidierStevens/DidierStevensSuite)

- **Phil Harvey (ExifTool)**  
  *Creator of ExifTool, the reference cross-platform metadata reader/writer.*  
  Website: [exiftool.org](https://exiftool.org)

- **Matthias Valcke (PyHanko)**  
  *Lead developer of PyHanko (PDF cryptographic signatures and RFC 3161 timestamping).*  
  GitHub: [github.com/MatthiasValcke/pyHanko](https://github.com/MatthiasValcke/pyHanko)

---

## Quick Start (Pre-compiled Executable)
1. Close any running instances.
2. Download/copy the executable from the `dist/` folder.
3. Run `ForensicDocAnalyzer_v1.0.exe`.
4. The app will automatically open in your default browser.

## Manual Installation
```bash
pip install -r requirements.txt
streamlit run forensic_doc_analyzer_patched.py
```

## Documentation
- 🇫🇷 [Guide_Forensique_v1.0.pdf](./Guide_Forensique_v1.0.pdf)
- 🇬🇧 [Forensic_Guide_v1.0.pdf](./Forensic_Guide_v1.0.pdf)
