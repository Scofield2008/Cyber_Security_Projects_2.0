from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import os

# Import from local modules
from .scanner import run_scan
from .db import init_db, save_result, get_results
from .exporter import export_json, export_pdf, export_csv

app = FastAPI()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# Create static directory if it doesn't exist
static_dir = os.path.join(BASE_DIR, "static")
if not os.path.exists(static_dir):
    os.makedirs(static_dir)

app.mount("/static", StaticFiles(directory=static_dir), name="static")

init_db()

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/scan", response_class=HTMLResponse)
async def scan(
    request: Request,
    provider: str = Form(...),
    aws_access_key: str = Form(""),
    aws_secret_key: str = Form(""),
    aws_session_token: str = Form(""),
    azure_tenant_id: str = Form(""),
    azure_client_id: str = Form(""),
    azure_client_secret: str = Form(""),
    gcp_key_path: str = Form("")
):
    # Run the scan
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
    
    # Save results to database
    for f in findings:
        try:
            save_result(
                provider=f.get("provider", provider),
                resource=f.get("resource") or f.get("resource_id") or "n/a",
                issue=f.get("title") or f.get("issue") or "finding",
                recommendation=f.get("remediation") or f.get("recommendation") or ""
            )
        except Exception as e:
            print(f"Error saving result: {e}")
            pass
    
    return RedirectResponse(url="/results", status_code=303)

@app.get("/results", response_class=HTMLResponse)
async def results(request: Request):
    data = get_results()
    return templates.TemplateResponse("results.html", {"request": request, "findings": data})

@app.get("/export/{format}")
async def export(format: str):
    try:
        if format == "json":
            path = export_json()
        elif format == "pdf":
            path = export_pdf()
        elif format == "csv":
            path = export_csv()
        else:
            return {"error": "Unsupported format"}
        return FileResponse(path, filename=os.path.basename(path))
    except Exception as e:
        return {"error": f"Export failed: {str(e)}"}

# Health check endpoint
@app.get("/health")
async def health():
    return {"status": "healthy"}
