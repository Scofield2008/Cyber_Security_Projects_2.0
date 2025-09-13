# app/main.py
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import os

from .scanner import run_scan
from .db import init_db, save_result, get_results
from .exporter import export_json, export_pdf, export_csv

app = FastAPI()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
# Ensure static dir exists or comment this line out (we'll create it)
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")

init_db()

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/scan", response_class=HTMLResponse)
async def scan(
    request: Request,
    provider: str = Form(...),
    aws_access_key: str = Form(None),
    aws_secret_key: str = Form(None),
    aws_session_token: str = Form(None),
    azure_tenant_id: str = Form(None),
    azure_client_id: str = Form(None),
    azure_client_secret: str = Form(None),
    gcp_key_path: str = Form(None)   # optional path to GCP service account JSON on server
):
    """
    Accepts credentials from the form (optional). If fields are empty, boto3/azure/gcloud default auth will be used.
    """
    # pass credentials down to the scanner
    findings = run_scan(
        provider=provider,
        aws_access_key=aws_access_key or None,
        aws_secret_key=aws_secret_key or None,
        aws_session_token=aws_session_token or None,
        azure_tenant_id=azure_tenant_id or None,
        azure_client_id=azure_client_id or None,
        azure_client_secret=azure_client_secret or None,
        gcp_key_path=gcp_key_path or None
    )

    # save to DB (normalize keys)
    for f in findings:
        try:
            save_result(
                provider=f.get("provider", provider),
                resource=f.get("resource") or f.get("resource_id") or "n/a",
                issue=f.get("title") or f.get("issue") or "finding",
                recommendation=f.get("remediation") or f.get("recommendation") or ""
            )
        except Exception:
            # don't break on DB errors; continue saving others
            pass

    # redirect to results page (results page reads DB)
    return RedirectResponse(url="/results", status_code=303)


@app.get("/results", response_class=HTMLResponse)
async def results(request: Request):
    data = get_results()
    return templates.TemplateResponse("results.html", {"request": request, "findings": data})


@app.get("/export/{format}")
async def export(format: str):
    if format == "json":
        path = export_json()
    elif format == "pdf":
        path = export_pdf()
    elif format == "csv":
        path = export_csv()
    else:
        return {"error": "Unsupported format"}
    return FileResponse(path, filename=os.path.basename(path))
