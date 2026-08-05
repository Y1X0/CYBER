"""Report generation and rendering (executive + technical, HTML + PDF)."""

from guardian_ai.reporting.generator import generate_report_content
from guardian_ai.reporting.html import render_html
from guardian_ai.reporting.pdf import render_pdf

__all__ = ["generate_report_content", "render_html", "render_pdf"]
