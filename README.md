# VirusTotal Detection Report Pipeline

Pipeline that:
- Accepts installer download links
- Scans them via VirusTotal API
- Detects antivirus hits
- Checks existing documentation in Google Sheets
- Appends new detections when undocumented
