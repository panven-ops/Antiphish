from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from models import AnalyzeRequest, AnalyzeResponse
from analyzer import analyze
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title = "Anti_phishing")

app.add_middleware(CORSMiddleware,
                   allow_origins = ["http://localhost:5173"],
                   allow_methods = ["POST", "GET"],
                   allow_headers = ["Content-Type"])

@app.get("/health")
def health():

    return{"status": "OKK"}


@app.post("/analyze", response_model = AnalyzeResponse)
async def analyze_req(request:AnalyzeRequest):

    return await analyze(request)

