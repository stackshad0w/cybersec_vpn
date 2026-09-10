import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

SCREEN_FILES = {
    "index.html": 274,        # SOC Security Dashboard
    "analyze.html": 286,      # Analyze PCAP Capture
    "results.html": 282,      # Analysis Result & Crypto Deep-Dive
    "traffic-ai.html": 288,   # Traffic AI & Metadata Exposure
}

NAV_REPLACEMENTS = [
    (r'href="#"(\s+data-path="dashboard")', r'href="/"\1'),
    (r'href="#"(\s+data-path="analyze-pcap")', r'href="/analyze.html"\1'),
    (r'href="#"(\s+data-path="analyses")', r'href="/results.html"\1'),
    (r'href="#"(\s+data-path="vpn-profiles")', r'href="/results.html"\1'),
    (r'href="#"(\s+data-path="findings-and-threats")', r'href="/results.html#findings"\1'),
    (r'href="#"(\s+data-path="traffic-ai")', r'href="/traffic-ai.html"\1'),
    (r'href="#"(\s+data-path="packet-explorer")', r'href="/results.html"\1'),
    (r'href="#"(\s+data-path="reports")', r'href="/results.html#reports"\1'),
    (r'href="#"(\s+data-path="settings")', r'href="/"\1'),
]

def main():
    frontend_dir = BASE_DIR / "frontend"
    frontend_dir.mkdir(parents=True, exist_ok=True)

    for target_name, step_num in SCREEN_FILES.items():
        src_path = Path(f"C:/Users/lenovo/.gemini/antigravity-ide/brain/5734d4d4-432b-4265-b24c-75426a32b8c7/.system_generated/steps/{step_num}/content.md")
        with open(src_path, "r", encoding="utf-8") as f:
            raw_text = f.read()

        html_start = raw_text.find("<!DOCTYPE html>")
        if html_start == -1:
            print(f"Error: <!DOCTYPE html> not found in step {step_num}")
            continue

        html_content = raw_text[html_start:]

        # Fix navigation links
        for pattern, repl in NAV_REPLACEMENTS:
            html_content = re.sub(pattern, repl, html_content)

        # Inject integration script before </body>
        script_tag = '<script src="/static/stitch_integration.js"></script></body>'
        if "</body>" in html_content:
            html_content = html_content.replace("</body>", script_tag)
        else:
            html_content += script_tag

        out_path = frontend_dir / target_name
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"Successfully created {out_path.name} from Stitch screen (step {step_num})")

if __name__ == "__main__":
    main()
