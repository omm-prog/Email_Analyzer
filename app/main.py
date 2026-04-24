from pathlib import Path

from fastapi import FastAPI, File, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.analyzers.email_analyzer import analyze_email


BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="Email Forensics Tool", version="1.0.0")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


@app.get("/", response_class=HTMLResponse)
async def upload_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="upload.html",
        context={"request": request, "error": ""},
    )


@app.post("/analyze", response_class=HTMLResponse)
async def analyze(request: Request, file: UploadFile = File(...)) -> HTMLResponse:
    raw_bytes = await file.read()
    if not raw_bytes:
        return templates.TemplateResponse(
            request=request,
            name="upload.html",
            context={"request": request, "error": "Please upload a non-empty email file."},
            status_code=400,
        )

    try:
        result = await analyze_email(raw_bytes)
    except Exception:
        return templates.TemplateResponse(
            request=request,
            name="upload.html",
            context={
                "request": request,
                "error": "Invalid email format. Please upload a valid email/.eml file.",
            },
            status_code=400,
        )

    return templates.TemplateResponse(
        request=request,
        name="result.html",
        context={
            "request": request,
            "filename": file.filename or "uploaded-email",
            "result": result,
        },
    )
