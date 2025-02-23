from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import logging
import json
import os
import sqlite3
import re
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict this in production!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("phishing_detector.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

DB_PATH = "phishing_detector.db"

def init_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE,
            added_on TEXT)''')
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        logger.error(f"Database initialization error: {e}")
        raise  # Re-raise the exception to stop the app

init_db()

# URL Model (This was missing!)
class URLCheckRequest(BaseModel):
    url: str

def is_blacklisted(url: str) -> bool:
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT url FROM blacklist WHERE url=?", (url,))
        result = cursor.fetchone()
        conn.close()
        return result is not None
    except sqlite3.Error as e:
        logger.error(f"Database error: {e}")
        return False  # Or raise an exception if you prefer

def analyze_url(url: str) -> bool:
    phishing_patterns = [
        r"https?://.free-gift.",
        r"https?://.bank-login.",
        r"https?://.password-reset.",
        r"https?://.\d{5,}.",
    ]
    for pattern in phishing_patterns:
        if re.search(pattern, url):
            return True
    return False

@app.post("/check_url/")
async def check_url(request: URLCheckRequest):
    url = request.url.lower()

    try:
        if is_blacklisted(url):
            logger.info(f"Blacklisted URL detected: {url}")
            return {"status": "phishing", "reason": "URL is blacklisted"}

        if analyze_url(url):
            logger.warning(f"Suspicious URL detected: {url}")
            return {"status": "suspicious", "reason": "Matches phishing pattern"}

        logger.info(f"URL is safe: {url}")
        return {"status": "safe", "reason": "No phishing patterns detected"}

    except Exception as e:
        logger.error(f"Error processing URL: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

@app.post("/add_blacklist/")
async def add_blacklist(request: URLCheckRequest):
    url = request.url.lower()

    try:
        if is_blacklisted(url):
            return {"message": "URL is already in the blacklist"}

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO blacklist (url, added_on) VALUES (?, ?)", (url, datetime.now().isoformat()))
        conn.commit()
        conn.close()

        logger.info(f"URL added to blacklist: {url}")
        return {"message": "URL added to blacklist"}

    except sqlite3.Error as e:  # Catch specific exception
        logger.error(f"Error adding URL to blacklist: {e}")
        raise HTTPException(status_code=500, detail="Database Error") # More specific error

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


if __name__ == "_main_":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)