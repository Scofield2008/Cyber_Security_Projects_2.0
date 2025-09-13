# app/exporter.py
import json
import csv
import os
from datetime import datetime
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from .db import get_results

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def export_json():
    """Export scan results to a JSON file"""
    results = get_results()
    findings = [
        {
            "provider": r.provider,
            "resource": r.resource,
            "issue": r.issue,
            "recommendation": r.recommendation
        }
        for r in results
    ]
    data = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "findings": findings
    }

    path = os.path.join(BASE_DIR, "report.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


def export_csv():
    """Export scan results to a CSV file"""
    results = get_results()
    path = os.path.join(BASE_DIR, "report.csv")

    with open(path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["provider", "resource", "issue", "recommendation"])
        for r in results:
            writer.writerow([r.provider, r.resource, r.issue, r.recommendation])

    return path


def export_pdf():
    """Export scan results to a PDF file"""
    results = get_results()
    path = os.path.join(BASE_DIR, "report.pdf")

    c = canvas.Canvas(path, pagesize=letter)
    width, height = letter
    y = height - 50

    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, "CSPM Lite Scan Report")
    y -= 40

    c.setFont("Helvetica", 10)
    for r in results:
        text = f"Provider: {r.provider} | Resource: {r.resource} | Issue: {r.issue} | Recommendation: {r.recommendation}"
        c.drawString(50, y, text)
        y -= 15
        if y < 50:  # new page
            c.showPage()
            c.setFont("Helvetica", 10)
            y = height - 50

    c.save()
    return path


        