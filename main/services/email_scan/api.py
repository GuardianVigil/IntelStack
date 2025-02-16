from typing import Dict, Any
from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from .email_analyzer import EmailHeaderAnalyzer

router = APIRouter()
analyzer = EmailHeaderAnalyzer()

@router.post("/analyze")
async def analyze_email_headers(email_headers: str = Form(...)) -> Dict[str, Any]:
    """
    Analyze email headers and return comprehensive analysis results.
    """
    try:
        results = analyzer.parse_headers(email_headers)
        return {
            "status": "success",
            "data": results
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/analyze/file")
async def analyze_email_file(file: UploadFile = File(...)) -> Dict[str, Any]:
    """
    Analyze email headers from an uploaded file.
    """
    try:
        content = await file.read()
        email_headers = content.decode('utf-8')
        results = analyzer.parse_headers(email_headers)
        return {
            "status": "success",
            "data": results
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
