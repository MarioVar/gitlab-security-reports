import json
import sys
import os
import uuid
from datetime import datetime
from markdown import markdown
from tqdm import tqdm

# Colori per severità
severity_colors = {
    "Critical": "Crimson",
    "High": "Tomato",
    "Medium": "Orange",
    "Low": "MediumSeaGreen",
    "Info": "SteelBlue"
}

def normalize_vuln(vuln):
    modal_html = ""

    # Description e Solution
    description = markdown(vuln.get("description", ""))
    solution = markdown(vuln.get("solution", ""))

    # Severity
    severity = vuln.get("severity", "Unknown")
    color = severity_colors.get(severity, "Black")
    formatted_severity = f"<span style='color:{color}'><strong>{severity}</strong></span>"

    # Details → modal
    details_id = f"details-{uuid.uuid4().hex}"
    vulnerable_package = vuln.get("details", {}).get("vulnerable_package", {}).get("value", "N/A")
    vendor_status = vuln.get("details", {}).get("vendor_status", {}).get("value", "N/A")

    details_button = f'''
    <button class="btn btn-sm btn-outline-dark" data-bs-toggle="modal" data-bs-target="#{details_id}">Show</button>
    '''
    modal_html += f'''
    <div class="modal fade" id="{details_id}" tabindex="-1">
      <div class="modal-dialog  modal-xl"><div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title">Details</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
        </div>
        <div class="modal-body">
          <p><strong>Vulnerable Package:</strong> {vulnerable_package}</p>
          <p><strong>Vendor Status:</strong> {vendor_status}</p>
        </div>
      </div></div>
    </div>
    '''

    # Location → modal
    location_id = f"location-{uuid.uuid4().hex}"
    location = vuln.get("location", {})
    operating_system = location.get("operating_system", "N/A")
    image = location.get("image", "N/A")
    dependency = location.get("dependency", {}).get("package", {}).get("name", "N/A")
    version = location.get("dependency", {}).get("version", "N/A")

    location_button = f'''
    <button class="btn btn-sm btn-outline-secondary" data-bs-toggle="modal" data-bs-target="#{location_id}">Show</button>
    '''
    modal_html += f'''
    <div class="modal fade" id="{location_id}" tabindex="-1">
      <div class="modal-dialog  modal-xl"><div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title">Location</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
        </div>
        <div class="modal-body">
          <p><strong>OS:</strong> {operating_system}</p>
          <p><strong>Image:</strong> {image}</p>
          <p><strong>Dependency:</strong> {dependency}:{version}</p>
        </div>
      </div></div>
    </div>
    '''

    return {
        "description": description,
        "solution": solution,
        "severity": formatted_severity,
        "details": details_button,
        "location": location_button,
        'sev-id':severity,
    }, modal_html


def main():
    if len(sys.argv) < 2:
        print("Usage: python generate_report.py <file1.json> [file2.json ...]")
        sys.exit(1)

    all_vulns = []
    modals_html = ""

    for path in tqdm(sys.argv[1:], desc="Processing files"):
        try:
            with open(path) as f:
                data = json.load(f)
                for vuln in data.get("vulnerabilities", []):
                    norm, modal = normalize_vuln(vuln)
                    all_vulns.append(norm)
                    modals_html += modal
        except Exception as e:
            print(f"[!] Error processing {path}: {e}")

    if not all_vulns:
        print("[!] No valid vulnerabilities.")
        sys.exit(1)

    rows = ""
    for vuln in all_vulns:
        # rows += "<tr>" + "".join(f"<td>{vuln[col]}</td>" for col in ["description", "solution", "severity", "details", "location"]) + "</tr>\n"
        rows += f"<tr data-severity='{vuln['sev-id']}'>"
        for col in ["description", "solution", "severity", "details", "location"]:
            rows += f"<td>{vuln[col]}</td>"
        rows += "</tr>\n"

    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dependency Vulnerability Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <style>
        body {{
            background-color: #f8f9fa;
            padding: 40px;
        }}
        table {{
            table-layout: fixed;
            word-wrap: break-word;
        }}
        th {{
            background-color: #f1f1f1;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Dependency Vulnerability Report</h1>
        <p><strong>Generated:</strong> {timestamp}</p>

          <div class="mb-3">
            <strong>Filter by severity:</strong><br>
            <button class="btn btn-outline-secondary btn-sm filter-btn" onclick="filterTable('all')">All</button>
            <button class="btn btn-outline-danger btn-sm filter-btn" onclick="filterTable('Critical')">Critical</button>
            <button class="btn btn-outline-danger btn-sm filter-btn" onclick="filterTable('High')">High</button>
            <button class="btn btn-outline-warning btn-sm filter-btn" onclick="filterTable('Medium')">Medium</button>
            <button class="btn btn-outline-success btn-sm filter-btn" onclick="filterTable('Low')">Low</button>
            <button class="btn btn-outline-info btn-sm filter-btn" onclick="filterTable('Info')">Info</button>
        </div>

      

        <table id="vuln-table" class="table table-bordered table-sm" id="vuln-table">
            <thead>
                <tr>
                    <th style="width:25%">Description</th>
                    <th style="width:15%">Solution</th>
                    <th style="width:10%">Severity</th>
                    <th style="width:15%">Details</th>
                    <th style="width:15%">Location</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </div>
    {modals_html}

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
</body>
</html>"""

    with open("container_scan_report.html", "w", encoding="utf-8") as f:
        f.write(html)

    print("[✓] Report generated: container_scan_report.html")


if __name__ == "__main__":
    main()

