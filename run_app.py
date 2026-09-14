import os
import sys
import multiprocessing
import webbrowser
import time
import threading
import socket

def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]

def get_script_dir():
    if getattr(sys, 'frozen', False):
        return getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.dirname(os.path.abspath(__file__))

def launch():
    multiprocessing.freeze_support()

    script_dir = get_script_dir()
    app_path = os.path.join(script_dir, "forensic_doc_analyzer_patched.py")
    
    port = 8501
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('127.0.0.1', 8501))
    sock.close()
    if result == 0:
        port = find_free_port()

    print("=" * 65)
    print("  Forensic Doc Analyzer v1.0.0")
    print("  Conçu & Signé par Dam-FOR3K (avec l'aide de l'IA Antigravity)")
    print(f"  Démarrage sur http://localhost:{port} ...")
    print("=" * 65)

    if not os.environ.get("FORENSIC_BROWSER_OPENED"):
        os.environ["FORENSIC_BROWSER_OPENED"] = "1"
        def open_browser():
            time.sleep(2.0)
            webbrowser.open(f"http://localhost:{port}")

        threading.Thread(target=open_browser, daemon=True).start()

    from streamlit.web import cli as stcli
    
    sys.argv = [
        "streamlit", "run", app_path,
        "--global.developmentMode=false",
        "--server.headless=true",
        "--browser.gatherUsageStats=false",
        "--server.maxUploadSize=1024",
        f"--server.port={port}"
    ]
    
    try:
        stcli.main()
    except SystemExit:
        pass
    except Exception as e:
        print(f"\n[Erreur de démarrage] : {e}")
        input("\nAppuyez sur Entrée pour quitter...")

if __name__ == "__main__":
    multiprocessing.freeze_support()
    launch()
