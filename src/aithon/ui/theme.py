"""CRT retro terminal theme."""

COLORS = {
    "bg": "#0a0a0a",
    "fg": "#00ff41",
    "fg_dim": "#00802a",
    "fg_bright": "#66ff8c",
    "accent": "#ff6600",
    "danger": "#ff0033",
    "border": "#004d1a",
    "header_bg": "#001a00",
}

SEVERITY_COLORS = {
    "CRITICAL": "#ff0033",
    "HIGH": "#ff6600",
    "MEDIUM": "#ffcc00",
    "LOW": "#00802a",
}

CRT_CSS = """
Screen {
    background: #0a0a0a;
}

#header {
    dock: top;
    height: 3;
    background: #001a00;
    color: #00ff41;
    text-align: center;
    text-style: bold;
    border-bottom: solid #004d1a;
}

#footer {
    dock: bottom;
    height: 1;
    background: #001a00;
    color: #00802a;
}

#scan-log {
    height: 1fr;
    background: #0a0a0a;
    color: #00ff41;
    border: solid #004d1a;
    padding: 1;
    overflow-y: auto;
}

#findings-table {
    height: 2fr;
    background: #0a0a0a;
    border: solid #004d1a;
}

.severity-critical {
    color: #ff0033;
    text-style: bold;
}

.severity-high {
    color: #ff6600;
    text-style: bold;
}

.severity-medium {
    color: #ffcc00;
}

.severity-low {
    color: #00802a;
}

#splash-logo {
    text-align: center;
    color: #00ff41;
    text-style: bold;
    margin: 2;
}

#boot-log {
    height: 1fr;
    background: #0a0a0a;
    color: #00ff41;
    border: solid #004d1a;
    padding: 1;
}

#splash-prompt {
    text-align: center;
    color: #66ff8c;
    margin: 1;
}

#log-container {
    width: 1fr;
    height: 1fr;
}

#table-container {
    width: 2fr;
    height: 1fr;
}

#report-log {
    height: 1fr;
    background: #0a0a0a;
    color: #00ff41;
    border: solid #004d1a;
    padding: 1;
}

Button {
    background: #001a00;
    color: #00ff41;
    border: solid #004d1a;
    margin: 1;
}

Button:hover {
    background: #004d1a;
    color: #66ff8c;
}

DataTable {
    background: #0a0a0a;
    color: #00ff41;
}

DataTable > .datatable--header {
    background: #001a00;
    color: #66ff8c;
    text-style: bold;
}

DataTable > .datatable--cursor {
    background: #004d1a;
    color: #66ff8c;
}

ProgressBar {
    margin: 1 2;
}
"""
