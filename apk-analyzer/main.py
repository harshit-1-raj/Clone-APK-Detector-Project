# main.py - Main Flask application
from flask import Flask, request, jsonify, render_template, redirect, url_for
import os
import hashlib
import zipfile
import re
import uuid
import json
import datetime
import logging
from werkzeug.utils import secure_filename
import sqlite3
from apkanalyzer import APKAnalyzer
from database import Database
from config import Config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__, 
            static_folder='static',
            template_folder='templates')
app.config.from_object(Config)

# Initialize components
db = Database(app.config['DATABASE_PATH'])
analyzer = APKAnalyzer()

# Create necessary directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['TEMP_FOLDER'], exist_ok=True)

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def index():
    """Serve the main page"""
    return render_template('index.html')

@app.route('/upload')
def upload_page():
    """Serve the upload page"""
    return render_template('upload.html')

@app.route('/result/<int:scan_id>')
def result_page(scan_id):
    """Serve the result page for a specific scan"""
    scan_result = db.get_scan_by_id(scan_id)
    if not scan_result:
        return redirect(url_for('index'))
    
    return render_template('result.html', scan=scan_result)

@app.route('/result')
def results_list():
    """Serve the list of all scans"""
    page = request.args.get('page', 1, type=int)
    limit = 10
    offset = (page - 1) * limit
    
    results = db.get_recent_scans(limit, offset)
    
    return render_template('result.html', results=results, page=page)

@app.route('/api/analyze', methods=['POST'])
def analyze_apk():
    """API endpoint to analyze APK files"""
    try:
        # Check if the post request has the file part
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file format. Only APK files are allowed'}), 400
            
        # Generate unique filename to prevent collisions
        unique_filename = f"{uuid.uuid4()}_{secure_filename(file.filename)}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        file.save(file_path)
        logger.info(f"Saved uploaded file to {file_path}")
        
        # Run the analysis
        try:
            analysis_result = analyzer.analyze_apk(file_path)
            
            # Store analysis result in database
            scan_id = db.save_scan_result(
                original_filename=file.filename,
                file_hash=analysis_result['file_hash'],
                package_name=analysis_result['package_name'],
                safety_score=analysis_result['overall_safety_score'],
                assessment=analysis_result['assessment'],
                result_json=json.dumps(analysis_result)
            )
            
            # Add scan ID to result
            analysis_result['scan_id'] = scan_id
            
            return jsonify(analysis_result)
            
        except Exception as e:
            logger.error(f"Analysis error: {str(e)}", exc_info=True)
            return jsonify({'error': f'Analysis error: {str(e)}'}), 500
        finally:
            # Clean up the uploaded file
            if os.path.exists(file_path):
                os.remove(file_path)
                logger.info(f"Removed temporary file {file_path}")
    
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route('/api/results', methods=['GET'])
def get_scan_results():
    """Get list of recent scan results"""
    try:
        limit = request.args.get('limit', default=10, type=int)
        offset = request.args.get('offset', default=0, type=int)
        
        results = db.get_recent_scans(limit, offset)
        return jsonify({
            'results': results,
            'count': len(results),
            'offset': offset,
            'limit': limit
        })
    except Exception as e:
        logger.error(f"Error fetching results: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/results/<int:scan_id>', methods=['GET'])
def get_scan_detail(scan_id):
    """Get detailed results for a specific scan"""
    try:
        result = db.get_scan_by_id(scan_id)
        if not result:
            return jsonify({'error': 'Scan not found'}), 404
            
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error fetching scan detail: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/statistics', methods=['GET'])
def get_statistics():
    """Get overall statistics about analyzed APKs"""
    try:
        stats = db.get_stats()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error fetching statistics: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """API health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'APK Analyzer API',
        'timestamp': datetime.datetime.now().isoformat(),
        'version': app.config['VERSION']
    })

@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle file too large error"""
    return jsonify({
        'error': 'File too large',
        'max_size_mb': app.config['MAX_CONTENT_LENGTH'] / (1024 * 1024)
    }), 413

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def server_error(error):
    """Handle 500 errors"""
    logger.error(f"Server error: {str(error)}", exc_info=True)
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # Initialize database on startup
    with app.app_context():
        db.init_db()
    
    # Start the Flask application
    app.run(
        debug=app.config['DEBUG'],
        host=app.config['HOST'],
        port=app.config['PORT']
    )