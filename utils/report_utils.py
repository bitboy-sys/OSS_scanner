from typing import List, Dict
import json
from jinja2 import Template

def generate_report(results: List[Dict], output_format: str, config: Dict) -> str:
    """生成扫描报告"""
    if output_format == "json":
        return json.dumps(results, ensure_ascii=False, indent=2)
    elif output_format == "html":
        # 读取HTML模板并渲染
        with open("config/html_template.html", "r", encoding="utf-8") as f:
            template = Template(f.read())
        return template.render(results=results, config=config)
    else:  # text
        text_lines = []
        for result in results:
            text_lines.append(f"{result['risk']}: {result['msg']} ({result['url']})")
        return "\n".join(text_lines)