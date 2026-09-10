import json
from typing import Dict, Any

class JSONExporter:
    """
    Exports full analysis results and forensic metadata in structured JSON.
    """

    @classmethod
    def export(cls, analysis_data: Dict[str, Any], output_path: str = None) -> str:
        # Serializes with pretty printing
        content = json.dumps(analysis_data, indent=2, default=str)
        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(content)
        return content
