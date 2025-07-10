import json
import re
import sys
import os
from markdown import markdown
from json2html import json2html
import uuid

# Severity → color map
severity_colors = {
    "Critical": "Crimson",
    "High": "Tomato",
    "Medium": "Orange",
    "Low": "MediumSeaGreen",
    "Info": "SteelBlue"
}
def inject_severity_attr(html, severities):
    tr_pattern = re.compile(r"<tr>(\s*<td>.*?</td>)", re.DOTALL)
    matches = list(tr_pattern.finditer(html))

    if len(matches) != len(severities):
        print(f"[!] Warning: {len(matches)} rows vs {len(severities)} severities — skipping injection.")
        return html

    for i, match in enumerate(matches):
        original = match.group(0)
        replacement = f'<tr data-severity="{severities[i]}">{match.group(1)}'
        html = html.replace(original, replacement, 1)

    return html

def normalize_vulnerability(v):
    # Remove unused fields
    for key in ["id", "category"]:
        v.pop(key, None)

    # Markdown to HTML
    v["description"] = markdown(v.get("description", ""), extensions=["fenced_code"])

    # Format severity
    severity = v.get("severity", "Unknown")
    color = severity_colors.get(severity, "Black")
    v["severity"] = f"<b><font color='{color}' data-severity='{severity}'>{severity}</font></b>"

    # Scanner name
    v["scanner"] = v.get("scanner", {}).get("name", "Unknown")

    # Location
    loc = v.get("location", {})
    v["location"] = f"{loc.get('file', '?')}:{loc.get('start_line', '?')}"

    # Identifiers → modal
    identifiers = v.pop("identifiers", [])
    if identifiers:
        modal_id = f"modal-{uuid.uuid4().hex}"
        list_items = ""
        for ident in identifiers:
            id_type = ident.get("type", "Unknown")
            id_value = ident.get("value", "N/A")
            id_url = ident.get("url")
            if id_url:
                item = f'<li><strong>{id_type}</strong>: <a href="{id_url}" target="_blank">{id_value}</a></li>'
            else:
                item = f'<li><strong>{id_type}</strong>: {id_value}</li>'
            list_items += item + "\n"

        modal_html = f"""
<div class="modal fade" id="{modal_id}" tabindex="-1" aria-labelledby="{modal_id}-label" aria-hidden="true">
  <div class="modal-dialog modal-dialog-scrollable">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="{modal_id}-label">Identifiers</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body">
        <ul>{list_items}</ul>
      </div>
    </div>
  </div>
</div>
"""
        v["CVE"] = f'<button class="btn btn-sm btn-outline-primary" data-bs-toggle="modal" data-bs-target="#{modal_id}">Show CVEs</button>'
        return v, modal_html
    else:
        v["CVE"] = "<span class='text-muted'>None</span>"
        return v, ""

def main():
    if len(sys.argv) < 2:
        print("Usage: python generate_combined_report.py <file1.json> [file2.json] ...")
        sys.exit(1)

    all_vulnerabilities = []
    all_modals = ""

    for file_path in sys.argv[1:]:
        if not file_path.lower().endswith(".json") or not os.path.isfile(file_path):
            print(f"[!] Skipping invalid file: {file_path}")
            continue

        try:
            with open(file_path, "r") as f:
                data = json.load(f)

            if "vulnerabilities" not in data:
                print(f"[!] File '{file_path}' does not contain 'vulnerabilities' key.")
                continue

            for vuln in data["vulnerabilities"]:
                norm_vuln, modal_html = normalize_vulnerability(vuln)
                all_vulnerabilities.append(norm_vuln)
                all_modals += modal_html

        except Exception as e:
            print(f"[!] Failed to parse '{file_path}': {e}")

    if not all_vulnerabilities:
        print("[!] No valid vulnerabilities found. Aborting.")
        sys.exit(1)

    html_table = json2html.convert(
        all_vulnerabilities,
        escape=False,
        table_attributes='id="vuln-table" class="table table-bordered table-striped table-sm text-sm"'

    )

    # list of severities
    severity_list = [
        re.search(r"data-severity='([^']+)'", v["severity"]).group(1)
        for v in all_vulnerabilities
    ]
    html_table = inject_severity_attr(html_table, severity_list)

    html_table = html_table.replace("<th>description</th>", "<th style='width:45%'>Description</th>")

    html_output = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Combined SAST Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {{
            font-family: Arial, sans-serif;
            background-color: #f8f9fa;
            padding: 40px;
        }}
        h1 {{
            color: #333;
            margin-bottom: 30px;
        }}
        .table {{
            word-wrap: break-word;
            table-layout: fixed;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Combined SAST Vulnerability Report</h1>
                
          <div class="mb-3">
            <strong>Filter by severity:</strong><br>
            <button class="btn btn-outline-secondary btn-sm filter-btn" onclick="filterTable('all')">All</button>
            <button class="btn btn-outline-danger btn-sm filter-btn" onclick="filterTable('Critical')">Critical</button>
            <button class="btn btn-outline-danger btn-sm filter-btn" onclick="filterTable('High')">High</button>
            <button class="btn btn-outline-warning btn-sm filter-btn" onclick="filterTable('Medium')">Medium</button>
            <button class="btn btn-outline-success btn-sm filter-btn" onclick="filterTable('Low')">Low</button>
            <button class="btn btn-outline-info btn-sm filter-btn" onclick="filterTable('Info')">Info</button>
        </div>

        <div class="table-responsive">
            {html_table}
        </div>

        <script>
          function filterTable(sev) {{
              const rows = document.querySelectorAll('#vuln-table tbody tr');
              rows.forEach(row => {{
                  const severity = row.getAttribute("data-severity");
                  if (sev === 'all' || severity === sev) {{
                      row.style.display = '';
                  }} else {{
                      row.style.display = 'none';
                  }}
              }});
          }}
      </script> 

    </div>

    {all_modals}

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

    output_file = "combined_report.html"
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_output)
        print(f"[✓] Combined HTML report generated: {output_file}")
    except Exception as e:
        print(f"[!] Failed to write report: {e}")

if __name__ == "__main__":
    main()

