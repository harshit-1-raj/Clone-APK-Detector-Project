# config.py - Configuration settings for the APK analyzer
import os

class Config:
    # Application info
    VERSION = "1.0.0"
    
    # Upload configuration
    UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
    TEMP_FOLDER = os.path.join(os.path.dirname(__file__), "tmp")
    ALLOWED_EXTENSIONS = {'apk'}
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB max upload size
    
    # Server configuration
    DEBUG = True
    HOST = "0.0.0.0"
    PORT = 5000
    
    # Database configuration
    DATABASE_PATH = os.path.join(os.path.dirname(__file__), "database", "apk_scans.db")
    
    # Secret key for session
    SECRET_KEY = "your-secret-key-here"  # Change this in production
    
    # VirusTotal API (if used in production)
    VIRUSTOTAL_API_KEY = ""  # Add your API key here