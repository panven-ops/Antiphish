
# Antiphish Detector

A web app that scans emails or phones for phishing and scamming content.


## Features

- Input Type: email or phone
- Runs static and external APIs checks
- From the scan returns score, verdict and per check breakdown



## Tech Stack

**Frontend:** React

**Backend:** FastAPI, httpx, pydantic, asyncio

**External-APIs:** VirusTotal, URLhaus


## Project Structure

backend/

- main.py
- models.py
- analyzer.py
- checkings/
    - static_rules.py
    - external_apis.py

frontend/

- App.jsx

## Getting Started

### Prerequisites

- Python 3.12
- Node.js + Vite -> React.js
- API keys for VirusTotal and URLhaus


### Environment Variables

To run this project two environment variables are needed cause of the external API calls that are made to VirusTotal and URLhaus.

- VirusTotal: `VIRUS_API_KEY`
- URLhaus: `URL_HAUS_KEY`


### Run Locally



Start the backend

```bash
  cd backend
  source venv/bin/activate
  pip install -r requirements.txt

  uvicorn main:app --reload
```

Start the frontend

```bash
cd frontend
npm install
npm run dev
```

## API Reference

#### Request body

```http
  POST /analyze
```

| Parameter | Type     | Description                |
| :-------- | :------- | :------------------------- |
| `text` | `string` | `text for analysis` |
| `input_type` | `input_type` | `email or phone` |

#### Response



| Parameter | Type     | Description                       |
| :-------- | :------- | :-------------------------------- |
| `verdict`      | `string` | `safe - suspicious - dangerous` |
| `total_score`| `integer`| `cumulative score in accordance to risk`|
| `checks`| `list`| `name(if problem) - passed(yes - no) - score(threat -> score) - detail`|


## How it works

### Static checks
It scans the text in accordance to the input_type.
- email: Scans for typosquatting, brand-impersonation - specific keywords.
    - typosquatting: in most phising attacks, attackers change from the original letter or two.
    - brand-impersonation: attackers impersonating famous brands.
    - suspicious keywords: attackers use words like "urgent", "suspended", "act now" etc.

- phone: suspicious phone - prefixes.
    - phone-prefixes: commonly phishing phones are with prefixes like "+92" or "+66" from countries like Pakistan or Thailand, countries -> scam hubs


### External API calls
Scans the text with the help of external tools VirusTotal and URLhaus.
-VirusTotal: checks if the domain has been flagged by security vendors.

-URLhaus: checks if the scanned URL is being listed as active malware.

Both are running in parallel using asyncio for quicker results and more efficiency.

### Scoring
- Each potential threat has a score. 
- Total score is being generated from all the potential threats a text possess.
- Verdict is given in the end of the scan, where:

    - safe: 0 < total_score <= 20
    - suspicious: 20 < total_score <= 50
    - dangerous: total_score > 50


## License

[MIT](https://choosealicense.com/licenses/mit/)

