import os
import io
import re
import secrets
import hashlib
import string
import zipfile
from datetime import datetime, timedelta
from flask import (
    Flask, render_template, request, jsonify,
    redirect, url_for, send_from_directory,
    send_file, session, flash
)
from werkzeug.utils import secure_filename
from functools import wraps
import pandas as pd
import numpy as np
from pathlib import Path
import json
from docxtpl import DocxTemplate
from docx import Document
from num2words import num2words
from flask import flash
from io import BytesIO
from flask import send_file
import logging
from werkzeug.middleware.proxy_fix import ProxyFix
logging.basicConfig(level=logging.INFO)

# Import database manager
from database import db

# Simple rate limiting for approval actions
approval_rate_limit = {}  # {ip: {action: timestamp}}

def check_rate_limit(ip, action, limit_seconds=5):
    """Prevent multiple rapid actions from the same IP"""
    current_time = datetime.now()
    key = f"{ip}_{action}"
    
    if key in approval_rate_limit:
        last_action = approval_rate_limit[key]
        if (current_time - last_action).total_seconds() < limit_seconds:
            return False  # Rate limited
    
    approval_rate_limit[key] = current_time
    return True  # Allowed

# Load environment variables from .env file if it exists
try:
    from dotenv import load_dotenv
    load_dotenv()
    print("Loaded environment variables from .env file")
    
    # Store initial values for change detection
    INITIAL_ADMIN_EMAIL = os.getenv('ADMIN_EMAIL')
    INITIAL_ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')
    
except ImportError:
    print("python-dotenv not installed. Install with: pip install python-dotenv")
    print("Environment variables must be set manually")
    INITIAL_ADMIN_EMAIL = None
    INITIAL_ADMIN_PASSWORD = None

notifications_store = []
BASE_DIR      = os.path.dirname(__file__)
CLIENTS_FILE  = os.path.join(BASE_DIR, 'data', 'clients.xlsx')
app = Flask(__name__, static_folder=None)

# ─── Absolute paths ───────────────────────────────────────────────────────────
BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
EXCEL_FILE    = os.path.join(BASE_DIR, "PO_data.xlsx")
VENDOR_FILE   = os.path.join(BASE_DIR, "vendor_items.xlsx")
DATA_FILE     = os.path.join(BASE_DIR, "data.xlsx")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploaded_PO_docs")
UPLOAD_MRF    = os.path.join(BASE_DIR, "Upload_MRF")
DEPT_EMAIL_FILE =os.path.join(BASE_DIR, "department_emails.xlsx")
PURCHASE_ORDER_FOLDER = os.path.join(BASE_DIR, "Purchase_Order")
API_KEYS_FILE = os.path.join(BASE_DIR, 'api_keys.json')

os.makedirs(PURCHASE_ORDER_FOLDER, exist_ok=True)
# Create upload folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(UPLOAD_MRF, exist_ok=True)

def init_excel(path, cols):
    if not os.path.exists(path):
        pd.DataFrame(columns=cols).to_excel(path, index=False)

# Budget files are managed manually by the user
# No automatic budget file creation

# Updated init_excel call to include detailed charge columns
init_excel(EXCEL_FILE,  [
    "Date", "PO Number", "PR Number", "Project Number", "Project Name", 
    "Company Name", "Basic Amount", "PF Charges", "Freight Charges", 
    "GST Amount", "Other Charges", "Total Amount", "File Path", "PO Status",
    # Vendor and form fields
    "Vendor Code", "PO Requester Role", "PO Requester Email", "PO Date", "Delivery Date",
    "Your Reference", "Price Basis", "Payment Terms", "Ship To Location", "Ship To Address", 
    "Ship To GSTIN", "Bill To Company", "Bill To Address", "Bill To GSTIN",
    "PF Rate", "GST Rate", "Freight Rate", "Other Rate", "Number of Items",
    # Item fields
    "Item Name", "Additional Info", "Quantity", "UOM", "Unit Rate"])
init_excel(VENDOR_FILE, ["Vendor Code","Item Name","Additional Info"])
init_excel(DATA_FILE,   [
    "Project Number","Project Name","PR Number","Requisition Department","Discipline","Name","Requester Email","Date",
    "Item Type","Item Name","Item Description","Unit of Items","Measurement",
    "Unit Rate","Indicative Price","Budget Total","Remaining Budget","Material Requisition File"
])

# ─── Flask setup ──────────────────────────────────────────────────────────────
app = Flask(__name__)

# Trust reverse proxy headers for scheme/host and set canonical host/scheme
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
app.config['SERVER_NAME'] = os.getenv('SERVER_NAME', 'sphere.simonindia.ai')
app.config['PREFERRED_URL_SCHEME'] = os.getenv('PREFERRED_URL_SCHEME', 'https')

# Generate a strong secret key if not provided via environment
DEFAULT_SECRET_KEY = ''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(64))
SECRET_KEY = os.environ.get('SECRET_KEY', DEFAULT_SECRET_KEY)

# Security: Validate secret key
if SECRET_KEY == DEFAULT_SECRET_KEY:
    print("⚠️  WARNING: Using generated secret key. Set SECRET_KEY environment variable for production consistency.")

app.secret_key = SECRET_KEY
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# ─── Configuration ────────────────────────────────────────────────────────────
# Load sensitive data from environment variables with fallbacks
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')

ALLOWED_EXTENSIONS = {'pdf', 'docx', 'doc', 'xlsx', 'xls'}
EXCEL_DIRECTORIES = [
    os.path.join(BASE_DIR)
]
EXCEL_EXCLUDE_DIRS = {
    'venv', '__pycache__', '.git', '.idea', '.vscode',
    'static', 'templates', 'uploaded_PO_docs'
}
EXCEL_WHITELIST = {
    os.path.join(BASE_DIR, 'data.xlsx'),
    os.path.join(BASE_DIR, 'PO_data.xlsx'),
    os.path.join(BASE_DIR, 'vendor_items.xlsx'),
    os.path.join(BASE_DIR, 'department_emails.xlsx'),
    os.path.join(BASE_DIR, 'I2501F001_budget.xlsx')
}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit

# ─── Security Functions ──────────────────────────────────────────────────────
def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_file_upload(file):
    """Validate file upload security"""
    if not file or file.filename == '':
        return False, "No file selected"
    if not allowed_file(file.filename):
        return False, "File type not allowed"
    if file.content_length and file.content_length > MAX_FILE_SIZE:
        return False, "File too large (max 10MB)"
    return True, "OK"

def human_readable_size(num_bytes):
    step = 1024.0
    for unit in ['B','KB','MB','GB','TB']:
        if num_bytes < step:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= step
    return f"{num_bytes:.1f} PB"

def base64_urlsafe(s):
    import base64
    return base64.urlsafe_b64encode(s.encode('utf-8')).decode('ascii')

def list_excel_files():
    files = []
    seen = set()
    candidates = set()
    for root_dir in EXCEL_DIRECTORIES:
        try:
            for root, dirs, filenames in os.walk(root_dir):
                # prune excluded dirs
                try:
                    dirs[:] = [d for d in dirs if d not in EXCEL_EXCLUDE_DIRS]
                except NameError:
                    # If EXCEL_EXCLUDE_DIRS not defined yet, skip pruning
                    pass
                for name in filenames:
                    if name.lower().endswith(('.xlsx', '.xls')):
                        candidates.add(os.path.join(root, name))
        except Exception:
            continue
    candidates |= set(EXCEL_WHITELIST)
    for path in candidates:
        if not os.path.exists(path):
            continue
        # Constrain to project dir and exclude known system dirs
        if os.path.commonpath([os.path.abspath(path), BASE_DIR]) != os.path.abspath(BASE_DIR):
            continue
        try:
            rel_parent = os.path.relpath(os.path.dirname(path), BASE_DIR).split(os.sep)[0]
        except ValueError:
            continue
        if 'EXCEL_EXCLUDE_DIRS' in globals() and rel_parent in EXCEL_EXCLUDE_DIRS:
            continue
        if path in seen:
            continue
        seen.add(path)
        try:
            stat = os.stat(path)
            relpath = os.path.relpath(path, BASE_DIR)
            files.append({
                'name': os.path.basename(path),
                'path': path,
                'relpath': relpath.replace('\\', '/'),
                'size_human': human_readable_size(stat.st_size),
                'mtime_human': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M'),
                'safe_id': base64_urlsafe(relpath)
            })
        except Exception:
            continue
    files.sort(key=lambda x: x['name'].lower())
    return files

def sanitize_input(input_str, max_length=255):
    """Sanitize and validate string input"""
    if not input_str:
        return ""
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[<>"\']', '', str(input_str).strip())
    return sanitized[:max_length]

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_phone(phone):
    """Validate phone number format"""
    pattern = r'^[\d\s\-\+\(\)]{10,15}$'
    return re.match(pattern, phone) is not None

# ─── Authentication & Authorization ──────────────────────────────────────────
def require_auth(f):
    """Decorator to require authentication for routes"""
    def decorated_function(*args, **kwargs):
        # Check if user has valid session
        session_token = session.get('session_token')
        user_id = session.get('user_id')
        
        if not session_token or not user_id:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required', 'redirect': url_for('login')}), 401
            else:
                flash('Please log in to access this page.', 'error')
                return redirect(url_for('login'))
        
        # Validate session with database
        valid_user_id = db.validate_session(session_token)
        if not valid_user_id or valid_user_id != user_id:
            # Invalid session, clear it
            session.clear()
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.path.startswith('/api/'):
                return jsonify({'error': 'Session expired', 'redirect': url_for('login')}), 401
            else:
                flash('Session expired. Please log in again.', 'error')
                return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def require_admin(f):
    """Decorator to require admin privileges"""
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        
        # Check if user has admin role directly
        try:
            conn = db.get_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT role FROM users WHERE id = ?', (user_id,))
            user_result = cursor.fetchone()
            conn.close()
            
            if not user_result or user_result['role'] != 'Admin':
                flash('Admin privileges required.', 'error')
                return redirect(url_for('po_system'))
        except Exception as e:
            flash('Error checking admin privileges.', 'error')
            return redirect(url_for('po_system'))
        
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def require_permission(permission):
    """Decorator to require specific permission"""
    def decorator(f):
        def decorated_function(*args, **kwargs):
            user_id = session.get('user_id')
            if not user_id:
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.path.startswith('/api/'):
                    return jsonify({'error': 'Authentication required', 'redirect': url_for('login')}), 401
                else:
                    flash('Please log in to access this page.', 'error')
                    return redirect(url_for('login'))
            
            # Check if user has required permission
            if not db.check_permission(user_id, permission):
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.path.startswith('/api/'):
                    return jsonify({'error': 'Insufficient permissions'}), 403
                else:
                    flash('You do not have permission to access this feature.', 'error')
                    return redirect(url_for('po_system'))
            
            return f(*args, **kwargs)
        decorated_function.__name__ = f.__name__
        return decorated_function
    return decorator

# ─── API Key Management ─────────────────────────────────────────────────────
def load_api_keys():
    """Load API keys from file"""
    try:
        if os.path.exists(API_KEYS_FILE):
            with open(API_KEYS_FILE, 'r') as f:
                return json.load(f)
        return {}
    except Exception:
        return {}

def save_api_keys(api_keys):
    """Save API keys to file"""
    try:
        with open(API_KEYS_FILE, 'w') as f:
            json.dump(api_keys, f, indent=2)
        return True
    except Exception:
        return False

def require_api_key(f):
    """Decorator to require valid API key"""
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        if not api_key:
            return jsonify({'error': 'API key required'}), 401
        
        api_keys = load_api_keys()
        if api_key not in api_keys:
            return jsonify({'error': 'Invalid API key'}), 401
        
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# ─── File Path Security ─────────────────────────────────────────────────────
def secure_file_path(file_path):
    """Ensure file path is secure and within allowed directory"""
    # Normalize path and check for path traversal attempts
    normalized_path = os.path.normpath(file_path)
    if '..' in normalized_path or normalized_path.startswith('/'):
        return None
    return normalized_path

# ─── Shared PO form fields & labels ───────────────────────────────────────────
FIELDS = [
    'project_name','po_number','vendor_code','company','company_address','gst',
    'contact_person_name','contact_person_mobile','contact_person_email',
    'po_date','your_reference','price_basis',
    'delivery_date','payment_term','ship_to_location','ship_to_address',
    'ship_to_gstin','bill_to_company','bill_to_address','bill_to_gstin',
    'pf_rate','gst_rate','freight_rate','other_rate'
]
LABELS = {
    'vendor_code':'Vendor Code','company':'Vendor Name','po_number':'PO Number',
    'company_address':'Vendor Address','gst':'GST Number',
    'contact_person_name':'Contact Person','contact_person_mobile':'Contact Mobile',
    'contact_person_email':'Contact Email','po_date':'PO Date',
    'your_reference':'Your Reference','project_name':'Project Number',
    'price_basis':'Price Basis (INCOTERMS)','delivery_date':'Delivery Date',
    'payment_term':'Payment Terms','ship_to_location':'Ship To (Location)',
    'ship_to_address':'Ship To Address','ship_to_gstin':'Ship To GSTIN',
    'bill_to_company':'Bill To Company','bill_to_address':'Bill To Address',
    'bill_to_gstin':'Bill To GSTIN','pf_rate':'P&F Rate (%)',
    'gst_rate':'GST Rate (%)','freight_rate':'Freight Rate (%)',
    'other_rate':'Other Charges Rate (%)'
}

dept_email_df = pd.read_excel(DEPT_EMAIL_FILE, dtype=str).fillna('')
dept_email_df['Department'] = dept_email_df['Department'].astype(str)
dept_email_df['Email']      = dept_email_df['Email'].astype(str)

def send_email(from_addr: str, to_addr: str, subject: str, html_body: str, attachment_path=None, attachment_name=None):
    """
    Send email using Gmail SMTP instead of Outlook COM automation.
    
    Args:
        from_addr: Sender email address (for display)
        to_addr: Recipient email address
        subject: Email subject
        html_body: HTML email body
        attachment_path: Optional path to file to attach
        attachment_name: Optional name for the attachment
    """
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        from email.mime.base import MIMEBase
        from email import encoders
        import os
        from dotenv import load_dotenv
        
        # Load environment variables
        load_dotenv()
        
        # Get Gmail credentials from environment variables
        gmail_email = os.getenv('GMAIL_EMAIL', 'simonindia.ai@gmail.com')
        gmail_password = os.getenv('GMAIL_PASSWORD')
        smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        smtp_port = int(os.getenv('SMTP_PORT', '587'))
        smtp_use_tls = os.getenv('SMTP_USE_TLS', 'True').lower() == 'true'
        
        if not gmail_password:
            app.logger.error("GMAIL_PASSWORD environment variable not set")
            print(f"Email would be sent from {gmail_email} to {to_addr} with subject: {subject}")
            print("(Email functionality disabled - GMAIL_PASSWORD not configured)")
            return
        
        # Create message
        msg = MIMEMultipart('alternative')
        msg['From'] = gmail_email
        msg['To'] = to_addr
        msg['Subject'] = subject
        
        # Add HTML body
        html_part = MIMEText(html_body, 'html')
        msg.attach(html_part)
        
        # Add attachment if provided
        if attachment_path and os.path.exists(attachment_path):
            try:
                with open(attachment_path, "rb") as attachment:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(attachment.read())
                
                encoders.encode_base64(part)
                
                # Set attachment filename
                if attachment_name:
                    part.add_header('Content-Disposition', 'attachment', filename=attachment_name)
                else:
                    part.add_header('Content-Disposition', 'attachment', filename=os.path.basename(attachment_path))
                
                msg.attach(part)
                app.logger.info(f"Attachment added: {attachment_path}")
                
            except Exception as attach_error:
                app.logger.warning(f"Failed to attach file {attachment_path}: {attach_error}")
        
        # Connect to Gmail SMTP server
        server = smtplib.SMTP(smtp_server, smtp_port)
        if smtp_use_tls:
            server.starttls()
        
        # Login to Gmail
        server.login(gmail_email, gmail_password)
        
        # Send email
        server.send_message(msg)
        server.quit()
        
        app.logger.info(f"Email sent successfully from {gmail_email} to {to_addr}")
        
    except Exception as e:
        app.logger.error(f"Failed to send email from {from_addr} to {to_addr}: {str(e)}")
        print(f"Failed to send email: {str(e)}")
        # Don't raise the exception - just log it and continue

def create_modern_email_template(title, recipient_name, content, action_buttons=None, details_table=None, footer_text=None):
    """
    Create a modern, professional email template with consistent styling.
    
    Args:
        title: Email title/header
        recipient_name: Name of the recipient
        content: Main content paragraphs
        action_buttons: List of dicts with 'text', 'url', 'color' keys
        details_table: HTML table content for details
        footer_text: Optional footer text
    """
    
    # Modern CSS styles with improved button design and better spacing
    styles = """
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            line-height: 1.6; 
            color: #333; 
            margin: 0; 
            padding: 20px; 
            background-color: #f8f9fa; 
        }
        .email-container { 
            max-width: 600px; 
            margin: 0 auto; 
            background-color: #ffffff; 
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.12); 
            border-radius: 12px; 
            overflow: hidden;
        }
        .header { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: #000000; 
            padding: 10px 30px; 
            text-align: center; 
        }
        .header h1 { 
            margin: 0; 
            font-size: 22px; 
            font-weight: 700; 
            letter-spacing: -0.5px;
        }
        .header .subtitle { 
            margin: 8px 0 0 0; 
            font-size: 13px; 
            opacity: 0.9; 
            font-weight: 500;
        }
        .content { 
            padding: 10px; 
        }
        .greeting { 
            font-size: 16px; 
            margin-bottom: 20px; 
            color: #2c3e50; 
            font-weight: 600;
        }
        .main-content { 
            margin-bottom: 25px; 
        }
        .main-content p { 
            margin-bottom: 12px; 
            font-size: 15px; 
            line-height: 1.5;
        }
        .details-section { 
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); 
            border-radius: 10px; 
            padding: 20px; 
            margin: 20px 0; 
            border-left: 4px solid #667eea; 
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.06);
        }
        .details-section h3 { 
            margin: 0 0 15px 0; 
            color: #2c3e50; 
            font-size: 16px; 
            font-weight: 700; 
        }
        .details-table { 
            width: 100%; 
            border-collapse: collapse; 
            margin-top: 15px; 
            border-radius: 8px; 
            overflow: hidden;
        }
        .details-table th, .details-table td { 
            padding: 12px 15px; 
            text-align: left; 
            border-bottom: 1px solid #e9ecef; 
        }
        .details-table th { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            font-weight: 600; 
            color: white; 
            font-size: 14px; 
        }
        .details-table td { 
            font-size: 14px; 
            background-color: #ffffff;
        }
        .details-table tr:nth-child(even) td { 
            background-color: #f8f9fa; 
        }
        .details-table tr:hover td { 
            background-color: #e3f2fd; 
        }
        .action-buttons { 
            text-align: center; 
            margin: 35px 0; 
            padding: 20px; 
            background: linear-gradient(135deg, #f8f9fa 0%, #ffffff 100%); 
            border-radius: 10px; 
            border: 2px dashed #e9ecef;
        }
        .action-buttons h3 {
            margin: 0 0 20px 0;
            color: #2c3e50;
            font-size: 16px;
            font-weight: 600;
        }
        .btn { 
            display: inline-block; 
            padding: 16px 32px; 
            margin: 8px 15px; 
            text-decoration: none; 
            border-radius: 50px; 
            font-weight: 700; 
            font-size: 16px; 
            text-transform: uppercase; 
            letter-spacing: 0.5px; 
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); 
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.15); 
            border: none; 
            cursor: pointer; 
            min-width: 140px; 
            position: relative; 
            overflow: hidden;
        }
        .btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
            transition: left 0.5s;
        }
        .btn:hover::before {
            left: 100%;
        }
        .btn-primary { 
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%); 
            color: white; 
            box-shadow: 0 6px 20px rgba(40, 167, 69, 0.4);
        }
        .btn-primary:hover { 
            background: linear-gradient(135deg, #218838 0%, #1ea085 100%); 
            transform: translateY(-3px) scale(1.05); 
            box-shadow: 0 8px 25px rgba(40, 167, 69, 0.5);
        }
        .btn-danger { 
            background: linear-gradient(135deg, #dc3545 0%, #e74c3c 100%); 
            color: white; 
            box-shadow: 0 6px 20px rgba(220, 53, 69, 0.4);
        }
        .btn-danger:hover { 
            background: linear-gradient(135deg, #c82333 0%, #c0392b 100%); 
            transform: translateY(-3px) scale(1.05); 
            box-shadow: 0 8px 25px rgba(220, 53, 69, 0.5);
        }
        .btn-secondary { 
            background: linear-gradient(135deg, #6c757d 0%, #5a6268 100%); 
            color: white; 
            box-shadow: 0 6px 20px rgba(108, 117, 125, 0.4);
        }
        .btn-secondary:hover { 
            background: linear-gradient(135deg, #5a6268 0%, #495057 100%); 
            transform: translateY(-3px) scale(1.05); 
            box-shadow: 0 8px 25px rgba(108, 117, 125, 0.5);
        }
        .footer { 
            background-color: #f8f9fa; 
            padding: 20px 30px; 
            text-align: center; 
            border-top: 1px solid #e9ecef; 
        }
        .footer p { 
            margin: 0; 
            font-size: 13px; 
            color: #6c757d; 
        }
        .highlight { 
            background: linear-gradient(135deg, #fff3cd 0%, #ffeaa7 100%); 
            padding: 15px 20px; 
            border-radius: 8px; 
            border-left: 4px solid #ffc107; 
            margin: 20px 0; 
            box-shadow: 0 2px 8px rgba(255, 193, 7, 0.2);
        }
        .highlight strong { 
            color: #856404; 
        }
        .status-badge { 
            display: inline-block; 
            padding: 6px 15px; 
            border-radius: 25px; 
            font-size: 12px; 
            font-weight: 700; 
            text-transform: uppercase; 
            letter-spacing: 0.5px;
        }
        .status-pending { 
            background: linear-gradient(135deg, #fff3cd 0%, #ffeaa7 100%); 
            color: #856404; 
        }
        .status-approved { 
            background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%); 
            color: #155724; 
        }
        .status-rejected { 
            background: linear-gradient(135deg, #f8d7da 0%, #f5c6cb 100%); 
            color: #721c24; 
        }
        .amount-highlight { 
            font-size: 20px; 
            font-weight: 700; 
            color: #28a745; 
            text-shadow: 0 1px 2px rgba(40, 167, 69, 0.2);
        }
        .divider { 
            height: 2px; 
            background: linear-gradient(90deg, transparent, #e9ecef, transparent); 
            margin: 25px 0; 
            border-radius: 1px;
        }
    </style>
    """
    
    # Build action buttons HTML with improved design
    buttons_html = ""
    if action_buttons:
        buttons_html = '<div class="action-buttons">'
        buttons_html += '<h3>🔔 Action Required</h3>'
        for btn in action_buttons:
            color_class = btn.get('color', 'primary')
            buttons_html += f'<a href="{btn["url"]}" class="btn btn-{color_class}">{btn["text"]}</a>'
        buttons_html += '</div>'
    
    # Build details table HTML
    details_html = ""
    if details_table:
        details_html = f'<div class="details-section"><h3>📋 Details</h3>{details_table}</div>'
    
    # Build footer HTML
    footer_html = ""
    if footer_text:
        footer_html = f'<div class="footer"><p>{footer_text}</p></div>'
    
    # Complete email template with optimized spacing
    email_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    {styles}
</head>
<body>
    <div class="email-container">
        <div class="header">
            <h1>{title}</h1>
            <div class="subtitle">Purchase Order Management System</div>
        </div>
        <div class="content">
            <div class="main-content">
                {content}
            </div>
            {details_html}
            {buttons_html}
        </div>
        {footer_html}
    </div>
</body>
</html>"""
    
    return email_html

def add_notification(icon, text, ref):
    """Persist global notification and keep in-memory cache fresh."""
    try:
        db.create_system_notification(icon=icon, text=text, ref=ref)
    except Exception as e:
        app.logger.error(f"Failed to persist system notification: {e}")

    notifications_store.insert(0, {
        'icon': icon,
        'text': text,
        'ref': ref,
        'time': datetime.now().isoformat()
    })
    if len(notifications_store) > 50:
        notifications_store.pop()

def get_po_items_for_email(po_number):
    """Get item details for a PO to include in approval emails"""
    try:
        df_po = pd.read_excel(EXCEL_FILE, dtype=str).fillna('')
        df_po['PO Number'] = df_po['PO Number'].str.strip()
        po_rows = df_po[df_po['PO Number'] == po_number]

        if po_rows.empty:
            return []

        items = []
        for idx, row in po_rows.iterrows():
            item_data = {
                'name': row.get('Item Name', ''),
                'quantity': float(row.get('Quantity', 0)) if row.get('Quantity', '') else 0,
                'unit_rate': float(row.get('Unit Rate', 0)) if row.get('Unit Rate', '') else 0,
                'uom': row.get('UOM', ''),
                'additional_info': row.get('Additional Info', '')
            }
            items.append(item_data)

        return items
    except Exception as e:
        app.logger.error(f"Error getting PO items for email: {e}")
        return []

def get_pr_items_for_email(pr_number):
    """Get item details for a PR to include in approval emails"""
    try:
        df_pr = pd.read_excel(DATA_FILE, dtype=str).fillna('')
        df_pr['PR Number'] = df_pr['PR Number'].str.strip()
        pr_rows = df_pr[df_pr['PR Number'] == pr_number]

        if pr_rows.empty:
            return []

        items = []
        for idx, row in pr_rows.iterrows():
            item_data = {
                'Item Description': row.get('Item Description', ''),
                'Unit of Items': row.get('Unit of Items', ''),
                'Measurement': row.get('Measurement', ''),
                'Item Name': row.get('Item Name', '')
            }
            items.append(item_data)

        return items
    except Exception as e:
        app.logger.error(f"Error getting PR items for email: {e}")
        return []

def create_po_details_table(po_number, project_name, pr_number, company, total_amount, basic_amount, pf_amount, gst_amount, freight_amount, other_amount, items=None):
    """
    Create a consistent details table for PO emails.
    
    Args:
        po_number: PO number
        project_name: Project name/number
        pr_number: PR number
        company: Vendor/company name
        total_amount: Total PO amount
        basic_amount: Basic amount
        pf_amount: P&F amount
        gst_amount: GST amount
        freight_amount: Freight amount
        other_amount: Other charges amount
        items: List of items (optional)
    """
    
    # Build items table if provided
    items_html = ""
    if items:
        items_rows = ""
        for item in items:
            line_total = item.get('quantity', 0) * item.get('unit_rate', 0)
            items_rows += f"""
            <tr style="background-color:#f9f9f9;">
              <td style="border:1px solid #ddd; padding:8px; font-weight:600;">
                {item.get('name', '')}
              </td>
              <td style="border:1px solid #ddd; padding:8px; text-align:center;">
                {item.get('quantity', '')}
              </td>
              <td style="border:1px solid #ddd; padding:8px; text-align:center;">
                {item.get('unit_rate', '')}
              </td>
              <td style="border:1px solid #ddd; padding:8px; text-align:right;">
                {line_total:.2f}
              </td>
            </tr>
            """
        
        items_html = f"""
        <table style="width:100%;border-collapse:collapse;margin-top:15px;">
          <thead>
           <tr>
             <th style="border:1px solid #ddd;padding:8px;">Item Name</th>
             <th style="border:1px solid #ddd;padding:8px;">Qty</th>
             <th style="border:1px solid #ddd;padding:8px;">Unit Rate</th>
             <th style="border:1px solid #ddd;padding:8px;">Line Total</th>
           </tr>
          </thead>
          <tbody>
           {items_rows}
          </tbody>
        </table>
        """
    
    details_table = f"""
      <table class="details-table">
        <tr>
          <th>Field</th>
          <th>Value</th>
        </tr>
        <tr>
          <td><strong>PO Number</strong></td>
          <td class="amount-highlight">{po_number}</td>
        </tr>
        <tr>
          <td><strong>Project Number</strong></td>
          <td>{project_name}</td>
        </tr>
        <tr>
          <td><strong>Purchase Request</strong></td>
          <td>{pr_number}</td>
        </tr>
        <tr>
          <td><strong>Vendor/Company</strong></td>
          <td>{company}</td>
        </tr>
        <tr>
          <td><strong>Total PO Amount</strong></td>
          <td class="amount-highlight">₹{total_amount}</td>
        </tr>
        <tr>
          <td><strong>Basic Amount</strong></td>
          <td>₹{basic_amount}</td>
        </tr>
        <tr>
          <td><strong>P&F Amount</strong></td>
          <td>₹{pf_amount}</td>
        </tr>
        <tr>
          <td><strong>GST Amount</strong></td>
          <td>₹{gst_amount}</td>
        </tr>
        <tr>
          <td><strong>Freight Amount</strong></td>
          <td>₹{freight_amount}</td>
        </tr>
        <tr>
          <td><strong>Other Charges</strong></td>
          <td>₹{other_amount}</td>
        </tr>
      </table>
      {items_html}
    """
    
    return details_table

def create_pr_details_table(pr_number, project_number, department, requester_role, requester_email, total_budget, budget_deducted, remaining_budget, items=None, project_name=''):
    """
    Create a consistent details table for PR emails.
    
    Args:
        pr_number: PR number
        project_number: Project number
        department: Department name
        requester_role: Requester role
        requester_email: Requester email
        total_budget: Total budget before deduction
        budget_deducted: Amount deducted from budget
        remaining_budget: Remaining budget after deduction
        items: List of items (optional)
        project_name: Project name (optional)
    """
    
    # Build items table if provided
    items_html = ""
    if items:
        items_rows = ""
        for item in items:
            items_rows += f"""
            <tr style="background-color:#f9f9f9;">
              <td style="border:1px solid #ddd; padding:8px; font-weight:600;">
                {item.get('Item Name', '')}
              </td>
              <td style="border:1px solid #ddd; padding:8px;">
                {item.get('Item Description', '')}
              </td>
              <td style="border:1px solid #ddd; padding:8px; text-align:center;">
                {item.get('Unit of Items', '')}
              </td>
              <td style="border:1px solid #ddd; padding:8px; text-align:center;">
                {item.get('Measurement', '')}
              </td>
            </tr>
            """
        
        items_html = f"""
        <table style="width:100%;border-collapse:collapse;margin-top:15px;">
          <thead>
           <tr>
             <th style="border:1px solid #ddd;padding:8px;">Item Name</th>
             <th style="border:1px solid #ddd;padding:8px;">Description</th>
             <th style="border:1px solid #ddd;padding:8px;">Qty</th>
             <th style="border:1px solid #ddd;padding:8px;">UoM</th>
           </tr>
          </thead>
          <tbody>
           {items_rows}
          </tbody>
        </table>
        """
    
    # Only include budget rows if values are provided (PR emails may not have budgets)
    budget_rows = ""
    if any([str(total_budget).strip(), str(budget_deducted).strip(), str(remaining_budget).strip()]):
        budget_rows = f"""
        <tr>
          <td><strong>Total Budget (all depts before this PR)</strong></td>
          <td>₹{total_budget}</td>
        </tr>
        <tr>
          <td><strong>Budget Deducted from {department}</strong></td>
          <td class=\"amount-highlight\">₹{budget_deducted}</td>
        </tr>
        <tr>
          <td><strong>Remaining Budget in {department}</strong></td>
          <td>₹{remaining_budget}</td>
        </tr>
        """

    details_table = f"""
      <table class="details-table">
        <tr>
          <th>Field</th>
          <th>Value</th>
        </tr>
        <tr>
          <td><strong>PR Number</strong></td>
          <td class="amount-highlight">{pr_number}</td>
        </tr>
        <tr>
          <td><strong>Project</strong></td>
          <td>{f"{project_number} - {project_name}".strip(' - ') if project_name else project_number}</td>
        </tr>
        <tr>
          <td><strong>Department</strong></td>
          <td>{department}</td>
        </tr>
        <tr>
          <td><strong>Requested by</strong></td>
          <td>{requester_role} ({requester_email})</td>
        </tr>
        {budget_rows}
      </table>
      {items_html}
    """
    
    return details_table

# ─── Helpers ──────────────────────────────────────────────────────────────────
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS

def extract_counter(po_number: str) -> int:
    parts = po_number.rsplit('-', 1)
    if len(parts) == 2 and parts[1].isdigit():
        return int(parts[1])
    return 0

def get_next_PO_number(project_id: str) -> str:
    # Global PO sequence "47" + 7-digit increment, ignores project_id
    df = pd.read_excel(EXCEL_FILE, dtype=str).fillna('')
    series = df["PO Number"].dropna().astype(str).str.strip()

    # 1) Filter to only those that start with '47' followed by digits
    valid = series[series.str.match(r"^47\d+$")]

    # 2) Peel off the '47' prefix and convert the remaining 7-digit suffix to int
    if not valid.empty:
        nums = valid.str[2:].astype(int)
        next_seq = nums.max() + 1
    else:
        next_seq = 1

    # 3) Emit '47' + zero-padded 7-digit sequence
    return f"47{next_seq:07d}"

def get_next_PR_number(project_id: str, dept_code: str) -> str:
    # 1) Load all existing PR numbers
    df = pd.read_excel(DATA_FILE, dtype=str).fillna('')
    pr_series = df['PR Number'].astype(str).str.strip()

    # 2) Select ALL PRs that belong to this project (ignore dep_code)
    #    e.g. matches "PROJECTX-ANYCODE-PR-001"
    project_pattern = rf"^{re.escape(project_id)}-\d+-PR-\d+$"
    mask = pr_series.str.match(project_pattern)
    existing = pr_series[mask]

    # 3) Extract the 3-digit suffix (regardless of dept_code)
    if not existing.empty:
        nums = existing.str.extract(rf"{re.escape(project_id)}-\d+-PR-(\d+)$")[0] \
                       .astype(int)
        next_seq = nums.max() + 1
    else:
        next_seq = 1

    # 4) Build the new PR, inserting the dep_code but using the project_seq
    return f"{project_id}-{dept_code}-PR-{next_seq:03d}"

def load_budgets_df():
    """Deprecated: Use load_project_budgets_for_pr(project_number) instead."""
    app.logger.warning("load_budgets_df() is deprecated. Use load_project_budgets_for_pr(project_number).")
    return pd.DataFrame(columns=["Department", "Material_Budget", "Service_Budget"])

def load_project_budgets_for_pr(project_number):
    """
    Load budget data for a specific project.
    This function now strictly requires a project-specific budget file and will not fall back.
    """
    project_budget_file = get_project_budget_file_path(project_number)
    
    if not project_budget_file:
        # The file path function already logged the warning, so we can return an empty frame.
        return pd.DataFrame(columns=['Department', 'Material_Budget', 'Service_Budget'])
        
    try:
        # First read without dtype to see actual column names
        df_raw = pd.read_excel(project_budget_file)
        app.logger.info(f"[Budget Load] Raw columns from {project_budget_file}: {list(df_raw.columns)}")
        
        # Check if the expected columns exist (case-insensitive)
        expected_columns = ['Department', 'Material_Budget', 'Service_Budget']
        actual_columns = list(df_raw.columns)
        
        # Try to find columns with case-insensitive matching
        department_col = None
        material_budget_col = None
        service_budget_col = None
        
        for col in actual_columns:
            col_lower = col.lower()
            if 'department' in col_lower:
                department_col = col
            elif 'material' in col_lower and 'budget' in col_lower:
                material_budget_col = col
            elif 'service' in col_lower and 'budget' in col_lower:
                service_budget_col = col
        
        app.logger.info(f"[Budget Load] Found columns: Department='{department_col}', Material_Budget='{material_budget_col}', Service_Budget='{service_budget_col}'")
        
        # If we found the columns, use them; otherwise use the expected names
        if department_col and material_budget_col and service_budget_col:
            df = df_raw[[department_col, material_budget_col, service_budget_col]].copy()
            df.columns = ['Department', 'Material_Budget', 'Service_Budget']
        else:
            # Fall back to expected column names
            df = df_raw.copy()
            # Ensure we have the required columns
            if 'Department' not in df.columns:
                df['Department'] = ''
            if 'Material_Budget' not in df.columns:
                df['Material_Budget'] = 0
            if 'Service_Budget' not in df.columns:
                df['Service_Budget'] = 0
        
        # Convert budget columns to numeric
        df['Material_Budget'] = pd.to_numeric(df['Material_Budget'], errors='coerce').fillna(0)
        df['Service_Budget'] = pd.to_numeric(df['Service_Budget'], errors='coerce').fillna(0)
        df['Department'] = df['Department'].str.strip()
        
        app.logger.info(f"[Budget Load] Final columns: {list(df.columns)}")
        app.logger.info(f"[Budget Load] Final shape: {df.shape}")
        
        return df
    except Exception as e:
        app.logger.error(f"Failed to read project budget file {project_budget_file}: {e}")
        return pd.DataFrame(columns=['Department', 'Material_Budget', 'Service_Budget'])

def save_budgets_df(df):
    """Deprecated: Project budgets are managed per-project file; saving is handled where appropriate."""
    app.logger.warning("save_budgets_df() is deprecated. Budgets are per-project files.")

# ─── API Key Management ──────────────────────────────────────────────────────
def load_api_keys():
    """Load API keys from JSON file"""
    import json
    try:
        if os.path.exists(API_KEYS_FILE):
            with open(API_KEYS_FILE, 'r') as f:
                return json.load(f)
        else:
            return {}
    except Exception as e:
        app.logger.error(f"Failed to load API keys: {e}")
        return {}

def save_api_keys(api_keys):
    """Save API keys to JSON file"""
    import json
    try:
        with open(API_KEYS_FILE, 'w') as f:
            json.dump(api_keys, f, indent=2)
    except Exception as e:
        app.logger.error(f"Failed to save API keys: {e}")

def generate_api_key():
    """Generate a new API key"""
    return secrets.token_urlsafe(32)

def hash_api_key(api_key):
    """Hash an API key for secure storage"""
    return hashlib.sha256(api_key.encode()).hexdigest()

def create_api_key(name, description=""):
    """Create a new API key"""
    api_keys = load_api_keys()
    api_key = generate_api_key()
    api_key_hash = hash_api_key(api_key)
    
    api_keys[api_key_hash] = {
        'name': name,
        'description': description,
        'created_at': datetime.now().isoformat(),
        'last_used': None,
        'active': True
    }
    
    save_api_keys(api_keys)
    return api_key

def validate_api_key(api_key):
    """Validate an API key"""
    if not api_key:
        return False
    
    api_keys = load_api_keys()
    api_key_hash = hash_api_key(api_key)
    
    if api_key_hash in api_keys and api_keys[api_key_hash].get('active', False):
        # Update last used timestamp
        api_keys[api_key_hash]['last_used'] = datetime.now().isoformat()
        save_api_keys(api_keys)
        return True
    
    return False

def require_api_key(f):
    """Decorator to require API key authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        
        if not validate_api_key(api_key):
            return jsonify({
                'error': 'Unauthorized',
                'message': 'Valid API key required'
            }), 401
        
        return f(*args, **kwargs)
    return decorated_function

# Initialize default API key for Procore integration
def init_default_api_key():
    """Initialize a default API key for Procore integration"""
    api_keys = load_api_keys()
    if not api_keys:  # If no API keys exist, create default one
        default_key = create_api_key(
            'Procore Integration', 
            'Default API key for Procore financial data integration'
        )
        print(f"Default API key created for Procore integration: {default_key}")
        print("Please save this key securely - it won't be shown again!")
        return default_key
    return None

# Initialize default API key
init_default_api_key()


@app.route('/get_pr_numbers')
@require_auth
def get_pr_numbers():
    project_id = sanitize_input(request.args.get('project_id', ''))
    # 1) Load all PR records
    df = pd.read_excel(DATA_FILE, dtype=str).fillna('')
    # 2) Filter to selected project
    df_proj = df[df['Project Number'] == project_id]
   # 3) Only keep those marked Approved
    df_proj = df_proj[df_proj['PR Status'].str.strip().str.lower() == 'approved']
    # 4) Extract unique PR Numbers
    prs = (
        df_proj['PR Number']
          .dropna()
          .astype(str)
          .unique()
          .tolist()
    )
    return jsonify(pr_numbers=prs)






# ─── Dashboard & PO System ───────────────────────────────────────────────────
@app.route('/')
def index():
    """Redirect to login page"""
    return redirect(url_for('login'))

@app.route('/dashboard')
@require_auth
def dashboard():
    """Main dashboard after login"""
    try:
        user_id = session.get('user_id')
        user = db.get_user_by_id(user_id)
        
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('login'))
        
        return render_template('index.html', user=user)
        
    except Exception as e:
        app.logger.error(f"Error in dashboard: {str(e)}")
        flash('An error occurred while loading dashboard', 'error')
        return redirect(url_for('login'))

@app.route('/po_system')
@require_auth
def po_system():
    try:
        user_id = session.get('user_id')
        user = db.get_user_by_id(user_id)
        
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('login'))
        
        # Re-flash any pending flash message set during redirects to ensure visibility
        pending = session.get('pending_flash')
        if pending and isinstance(pending, dict):
            cat = pending.get('category') or 'info'
            msg = pending.get('message') or ''
            remaining = int(pending.get('remaining', 1))
            if msg:
                flash(msg, cat)
            if remaining > 1:
                pending['remaining'] = remaining - 1
                session['pending_flash'] = pending
            else:
                session.pop('pending_flash', None)

        # Budgets are project-specific; load them only when a project is selected in flows that need it
        dynamic_budgets = {}

        # Load existing PRs
        if os.path.exists(DATA_FILE):
            df_pr = pd.read_excel(DATA_FILE, dtype=str).fillna('')
            df_pr['Requisition Department'] = df_pr['Requisition Department'].str.strip()
            df_pr['Indicative Price'] = pd.to_numeric(df_pr['Indicative Price'], errors='coerce').fillna(0)
            all_projects = set(df_pr['Project Number'].unique())
            df_po = pd.read_excel(EXCEL_FILE, dtype=str).fillna('')
            used_projects = (
                df_po['PO Number'].dropna().astype(str).str.split('-PO-').str[0].unique()
            )
            projects = sorted(all_projects)
        else:
            projects = []

        df_clients = pd.read_excel(CLIENTS_FILE, dtype=str, engine='openpyxl').fillna('')
        clients = df_clients.to_dict(orient='records')
        
        return render_template(
            'po_system.html',
            user=user,
            fields=FIELDS,
            labels=LABELS,
            budgets=dynamic_budgets,
            date_str=datetime.now().strftime('%d-%m-%Y'),
            projects=projects,
            clients=clients
        )
        
    except Exception as e:
        app.logger.error(f"Error in po_system: {str(e)}")
        flash('An error occurred while loading dashboard', 'error')
        return redirect(url_for('login'))

@app.route('/add_client', methods=['POST'])
@require_auth
def add_client():
    # 1) Load existing clients
    df = pd.read_excel(
        CLIENTS_FILE,
        dtype=str,
        engine='openpyxl'
    ).fillna('')

    # 2) Determine next zero-padded code
    # Ensure codes are ints for max calculation
    df['code'] = df['code'].astype(int)
    next_code = f"{df['code'].max() + 1:02d}"

    name = sanitize_input(request.form.get('client_name', '').strip())
    if not name:
        return jsonify({"error": "Missing client_name"}), 400

    # 3) Append new row (using loc instead of deprecated append)
    df.loc[len(df)] = {'code': next_code, 'name': name}

    # 4) Write back to Excel with openpyxl engine
    df.to_excel(CLIENTS_FILE, index=False, engine='openpyxl')

    # 5) Return the new entry
    return jsonify(code=next_code, name=name)

@app.route('/add_project', methods=['POST'])
@require_auth
def add_project():
    try:
        # Debug logging
        app.logger.info(f"[add_project] Form data received: {dict(request.form)}")
        
        proj_code   = sanitize_input(request.form.get('project_code', '').strip())
        year        = sanitize_input(request.form.get('year', '').strip())
        client_code = sanitize_input(request.form.get('client_code', '').strip())
        sector_code = sanitize_input(request.form.get('sector_code', '').strip())
        project_name = sanitize_input(request.form.get('project_name', '').strip())
        
        # Validate required fields
        if not all([proj_code, year, client_code, sector_code, project_name]):
            missing_fields = []
            if not proj_code: missing_fields.append('project_code')
            if not year: missing_fields.append('year')
            if not client_code: missing_fields.append('client_code')
            if not sector_code: missing_fields.append('sector_code')
            if not project_name: missing_fields.append('project_name')
            
            app.logger.warning(f"[add_project] Missing required fields: {missing_fields}")
            return jsonify({'error': 'Missing required fields', 'missing': missing_fields}), 400
        
        prefix = f"{proj_code}{year}{client_code}{sector_code}"
        app.logger.info(f"[add_project] Generated prefix: {prefix}")

        # Load existing data
        app.logger.info(f"[add_project] Attempting to load DATA_FILE from: {DATA_FILE}")
        app.logger.info(f"[add_project] DATA_FILE exists: {os.path.exists(DATA_FILE)}")
        app.logger.info(f"[add_project] Current working directory: {os.getcwd()}")
        
        try:
            dfp = pd.read_excel(DATA_FILE, dtype=str).fillna('')
            app.logger.info(f"[add_project] Loaded existing data with {len(dfp)} rows")
            app.logger.info(f"[add_project] Columns in DATA_FILE: {list(dfp.columns)}")
        except FileNotFoundError:
            app.logger.info(f"[add_project] DATA_FILE not found, creating new dataframe")
            dfp = pd.DataFrame(columns=['Project Number', 'Project Name'])
        except Exception as e:
            app.logger.error(f"[add_project] Error loading DATA_FILE: {e}")
            return jsonify({'error': 'Failed to load existing data', 'message': str(e)}), 500
        
        # Ensure required columns exist
        if 'Project Number' not in dfp.columns:
            dfp['Project Number'] = ''
        if 'Project Name' not in dfp.columns:
            dfp['Project Name'] = ''
        
        # Filter existing project numbers that start with the prefix
        existing = dfp[dfp['Project Number'].str.startswith(prefix, na=False)]['Project Number']
        app.logger.info(f"[add_project] Found {len(existing)} existing projects with prefix {prefix}")
        
        if not existing.empty:
            # Extract the last 3 digits and convert to integers
            try:
                seqs = existing.str[-3:].astype(int)
                next_seq = seqs.max() + 1
                app.logger.info(f"[add_project] Next sequence number: {next_seq}")
            except Exception as e:
                app.logger.error(f"[add_project] Error parsing sequence numbers: {e}")
                next_seq = 1
        else:
            next_seq = 1
            
        project_number = f"{prefix}{next_seq:03d}"
        app.logger.info(f"[add_project] Generated project number: {project_number}")
        
        # Save the new project to data.xlsx
        new_row = pd.DataFrame({
            'Project Number': [project_number],
            'Project Name': [project_name]
        })
        dfp = pd.concat([dfp, new_row], ignore_index=True)
        
        try:
            dfp.to_excel(DATA_FILE, index=False)
            app.logger.info(f"[add_project] Successfully saved to {DATA_FILE}")
        except Exception as e:
            app.logger.error(f"[add_project] Error saving to DATA_FILE: {e}")
            return jsonify({'error': 'Failed to save project data', 'message': str(e)}), 500
        
        app.logger.info(f"[add_project] Successfully generated project: {project_number}")
        return jsonify(project_number=project_number)
        
    except Exception as e:
        app.logger.error(f"Error in add_project: {str(e)}")
        return jsonify({'error': 'Failed to generate project number', 'message': str(e)}), 500

# Route to serve approval pages
@app.route('/approval_page')
def approval_page():
    """Serve the approval pages template"""
    return render_template('approval_pages.html')

# ─── User Authentication Routes ───────────────────────────────────────────────

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """User registration page"""
    if request.method == 'GET':
        return render_template('signup.html')
    
    # Handle POST request for user registration
    try:
        data = request.get_json()
        
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        full_name = data.get('full_name', '').strip()
        password = data.get('password', '').strip()
        confirm_password = data.get('confirm_password', '').strip()
        
        # Validation
        if not all([username, email, full_name, password, confirm_password]):
            return jsonify({'success': False, 'message': 'All fields are required'})
        
        if password != confirm_password:
            return jsonify({'success': False, 'message': 'Passwords do not match'})
        
        if len(password) < 6:
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters long'})
        
        # Create user (pending approval)
        if db.create_user(username, email, password, full_name):
            return jsonify({'success': True, 'message': 'Account created successfully! Please wait for admin approval.'})
        else:
            return jsonify({'success': False, 'message': 'Username or email already exists'})
            
    except Exception as e:
        app.logger.error(f"Error in signup: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred during registration'})

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page"""
    if request.method == 'GET':
        return render_template('login.html')
    
    # Handle POST request for user login
    try:
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        
        if not email or not password:
            flash('Please provide both email and password', 'error')
            return redirect(url_for('login'))
        
        # Authenticate user with database
        user = db.authenticate_user(email, password)
        
        if user:
            # Create session
            session_token = db.create_session(user['id'])
            if session_token:
                session['session_token'] = session_token
                session['user_id'] = user['id']
                session['user_email'] = user['email']
                session['user_role'] = user['role']
                session['user_name'] = user['full_name']
                session['logged_in'] = True
                
                flash(f'Welcome back, {user["full_name"]}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Failed to create session', 'error')
                return redirect(url_for('login'))
        else:
            flash('Invalid email or password', 'error')
            return redirect(url_for('login'))
            
    except Exception as e:
        app.logger.error(f"Error in login: {str(e)}")
        flash('An error occurred during login', 'error')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    """User logout"""
    try:
        session_token = session.get('session_token')
        if session_token:
            db.invalidate_session(session_token)
        
        # Clear session
        session.clear()
        flash('You have been logged out successfully', 'info')
        
    except Exception as e:
        app.logger.error(f"Error in logout: {str(e)}")
    
    return redirect(url_for('login'))

@app.route('/profile')
@require_auth
def profile():
    """User profile page"""
    try:
        user_id = session.get('user_id')
        user = db.get_user_by_id(user_id)
        
        if user:
            return render_template('profile.html', user=user)
        else:
            flash('User not found', 'error')
            return redirect(url_for('po_system'))
            
    except Exception as e:
        app.logger.error(f"Error in profile: {str(e)}")
        flash('An error occurred while loading profile', 'error')
        return redirect(url_for('po_system'))

@app.route('/api/notifications')
@require_auth
def api_notifications():
    """Get combined recent system and user-specific notifications (persistent)."""
    try:
        user_id = session.get('user_id')
        system_notes = db.get_recent_system_notifications(limit=10)
        user_notes = db.get_user_notifications(user_id, limit=10)

        def normalize_system(n):
            return {
                'id': n.get('id'),
                'title': None,
                'message': n.get('text'),
                'type': 'system',
                'is_read': 0,
                'related_id': n.get('ref'),
                'icon': n.get('icon'),
                'created_at': n.get('created_at')
            }

        notifications = [normalize_system(n) for n in system_notes] + user_notes
        notifications.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        notifications = notifications[:20]

        return jsonify({'success': True, 'notifications': notifications})
    except Exception as e:
        app.logger.error(f"Error getting notifications: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to load notifications'}), 500

@app.route('/api/mark_notification_read', methods=['POST'])
@require_auth
def mark_notification_read():
    """Mark a notification as read"""
    try:
        user_id = session.get('user_id')
        notification_id = request.json.get('notification_id')
        
        if not notification_id:
            return jsonify({'success': False, 'message': 'Notification ID required'})
        
        if db.mark_notification_read(notification_id, user_id):
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Failed to mark notification as read'})
            
    except Exception as e:
        app.logger.error(f"Error marking notification read: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred'}), 500

@app.route('/api/feedback')
@require_auth
def api_feedback():
    """Get user feedback from database"""
    try:
        user_id = session.get('user_id')
        request_type = request.args.get('type')  # 'PR' or 'PO'
        
        feedback = db.get_user_feedback(user_id, request_type)
        
        return jsonify({
            'success': True,
            'feedback': feedback
        })
        
    except Exception as e:
        app.logger.error(f"Error getting feedback: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to load feedback'
        }), 500

@app.route('/api/update_profile', methods=['POST'])
@require_auth
def api_update_profile():
    """Update user profile information"""
    try:
        user_id = session.get('user_id')
        data = request.get_json()
        
        full_name = data.get('full_name', '').strip()
        department = data.get('department', '').strip()
        
        if not full_name:
            return jsonify({'success': False, 'message': 'Full name is required'})
        
        if db.update_user_profile(user_id, full_name, department):
            return jsonify({'success': True, 'message': 'Profile updated successfully'})
        else:
            return jsonify({'success': False, 'message': 'Failed to update profile'})
            
    except Exception as e:
        app.logger.error(f"Error updating profile: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred while updating profile'}), 500

@app.route('/api/change_password', methods=['POST'])
@require_auth
def api_change_password():
    """Change user password"""
    try:
        user_id = session.get('user_id')
        data = request.get_json()
        
        current_password = data.get('current_password', '').strip()
        new_password = data.get('new_password', '').strip()
        
        if not current_password or not new_password:
            return jsonify({'success': False, 'message': 'Both current and new passwords are required'})
        
        if len(new_password) < 8:
            return jsonify({'success': False, 'message': 'New password must be at least 8 characters long'})
        
        # Verify current password
        user = db.get_user_by_id(user_id)
        if not user:
            return jsonify({'success': False, 'message': 'User not found'})
        
        if not db.verify_password(current_password, db.get_password_hash(user['email'])):
            return jsonify({'success': False, 'message': 'Current password is incorrect'})
        
        # Change password
        if db.change_user_password(user_id, new_password):
            return jsonify({'success': True, 'message': 'Password changed successfully'})
        else:
            return jsonify({'success': False, 'message': 'Failed to change password'})
            
    except Exception as e:
        app.logger.error(f"Error changing password: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred while changing password'}), 500

@app.route('/update_admin_credentials', methods=['GET', 'POST'])
def update_admin_credentials():
    """Update admin credentials from environment variables"""
    if request.method == 'GET':
        return render_template('update_admin.html')
    
    try:
        # Get credentials from environment variables
        new_email = os.getenv('ADMIN_EMAIL')
        new_password = os.getenv('ADMIN_PASSWORD')
        
        if not new_email or not new_password:
            return jsonify({'success': False, 'message': 'ADMIN_EMAIL and ADMIN_PASSWORD environment variables not set'})
        
        # Update admin user in database
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Get admin user
        cursor.execute('SELECT id FROM users WHERE role = "Admin" LIMIT 1')
        admin_user = cursor.fetchone()
        
        if admin_user:
            admin_id = admin_user[0]
            # Update email and password
            new_password_hash = db.hash_password(new_password)
            cursor.execute('''
                UPDATE users 
                SET email = ?, password_hash = ? 
                WHERE id = ?
            ''', (new_email, new_password_hash, admin_id))
            
            conn.commit()
            conn.close()
            
            return jsonify({
                'success': True, 
                'message': f'Admin credentials updated successfully. New email: {new_email}'
            })
        else:
            conn.close()
            return jsonify({'success': False, 'message': 'No admin user found in database'})
            
    except Exception as e:
        app.logger.error(f"Error updating admin credentials: {str(e)}")
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/api/admin_env_vars')
def admin_env_vars():
    """Get current admin environment variables"""
    try:
        email = os.getenv('ADMIN_EMAIL', 'Not set')
        password = os.getenv('ADMIN_PASSWORD', 'Not set')
        
        return jsonify({
            'success': True,
            'email': email,
            'password': '••••••••' if password != 'Not set' else 'Not set'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/api/check_and_sync_env', methods=['POST'])
def check_and_sync_env():
    """Check environment variables and sync admin credentials if needed"""
    try:
        # Check for changes and sync if needed
        if check_env_changes():
            return jsonify({
                'success': True,
                'message': 'Environment variables checked and synced successfully'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to check environment variables'
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/user_configuration')
@require_admin
def user_configuration():
    """Admin user configuration page"""
    try:
        # Get current user info
        user_id = session.get('user_id')
        current_user = db.get_user_by_id(user_id)
        
        # Get all users and pending users
        all_users = db.get_all_users(user_id)
        pending_users = db.get_pending_users()
        
        return render_template('user_configuration.html', 
                             user=current_user,
                             all_users=all_users, 
                             pending_users=pending_users)
    except Exception as e:
        app.logger.error(f"Error in user_configuration: {str(e)}")
        flash('An error occurred while loading user configuration', 'error')
        return redirect(url_for('po_system'))

@app.route('/admin/data')
@require_admin
def admin_data_files():
    files = list_excel_files()
    return render_template('admin_data_files.html', files=files)

@app.route('/admin/data/download')
@require_admin
def admin_data_download():
    rel = request.args.get('rel', '')
    if not rel:
        # Fallback support if old cached UI sent 'path'
        legacy_path = request.args.get('path', '')
        if legacy_path:
            # If it's absolute, convert to rel; otherwise treat as rel
            abs_candidate = os.path.abspath(legacy_path)
            try:
                rel = os.path.relpath(abs_candidate, BASE_DIR)
            except Exception:
                rel = legacy_path
        else:
            return jsonify({'success': False, 'message': 'Missing rel path'}), 400
    # Normalize to absolute under BASE_DIR
    target_abs = os.path.abspath(os.path.join(BASE_DIR, rel))
    allowed_paths = {os.path.abspath(f['path']) for f in list_excel_files()}
    if target_abs not in allowed_paths or not os.path.isfile(target_abs):
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    directory = os.path.dirname(target_abs)
    filename = os.path.basename(target_abs)
    return send_from_directory(directory, filename, as_attachment=True)

@app.route('/admin/data/upload', methods=['POST'])
@require_admin
def admin_data_upload():
    rel = request.form.get('rel', '')
    file = request.files.get('file')
    if not rel:
        # Fallback support if old cached UI sent 'target_path'
        legacy_path = request.form.get('target_path', '')
        if legacy_path:
            abs_candidate = os.path.abspath(legacy_path)
            try:
                rel = os.path.relpath(abs_candidate, BASE_DIR)
            except Exception:
                rel = legacy_path
    if not rel or not file:
        return jsonify({'success': False, 'message': 'Missing target or file'}), 400
    if not (file.filename.lower().endswith('.xlsx') or file.filename.lower().endswith('.xls')):
        return jsonify({'success': False, 'message': 'Only .xlsx or .xls allowed'}), 400
    target_abs = os.path.abspath(os.path.join(BASE_DIR, rel))
    allowed_paths = {os.path.abspath(f['path']) for f in list_excel_files()}
    if target_abs not in allowed_paths or not os.path.isfile(target_abs):
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    try:
        backup_dir = os.path.join(BASE_DIR, 'backups')
        os.makedirs(backup_dir, exist_ok=True)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        base = os.path.basename(target_abs)
        backup_path = os.path.join(backup_dir, f"{base}.{ts}.bak")
        import shutil
        shutil.copy2(target_abs, backup_path)
        temp_path = target_abs + '.upload'
        file.save(temp_path)
        try:
            pd.read_excel(temp_path, nrows=1)
        except Exception:
            os.remove(temp_path)
            return jsonify({'success': False, 'message': 'Uploaded file is not a valid Excel'}), 400
        os.replace(temp_path, target_abs)
        return jsonify({'success': True, 'message': 'File replaced successfully'})
    except Exception as e:
        app.logger.error(f"Excel replace failed: {e}")
        return jsonify({'success': False, 'message': 'Server error'}), 500
@app.route('/api/approve_user', methods=['POST'])
@require_admin
def approve_user():
    """Approve a user and assign role/permissions"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        role = data.get('role')
        permissions = data.get('permissions', {})
        
        app.logger.info(f"Approving user {user_id} with role: {role}, permissions: {permissions}")
        
        if not user_id or not role:
            return jsonify({'success': False, 'message': 'User ID and role are required'})
        
        if db.approve_user(user_id, role, permissions):
            app.logger.info(f"✅ User {user_id} approved successfully with role: {role}")
            return jsonify({'success': True, 'message': 'User approved successfully'})
        else:
            app.logger.error(f"❌ Failed to approve user {user_id}")
            return jsonify({'success': False, 'message': 'Failed to approve user'})
            
    except Exception as e:
        app.logger.error(f"Error approving user: {str(e)}")
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/api/get_user_permissions/<int:user_id>')
@require_admin
def get_user_permissions(user_id):
    """Get user permissions for admin"""
    try:
        permissions = db.get_user_permissions(user_id)
        return jsonify({'success': True, 'permissions': permissions})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/update_user', methods=['POST'])
@require_admin
def update_user():
    """Update user permissions"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        permissions = data.get('permissions', {})
        
        app.logger.info(f"Updating user {user_id} permissions: {permissions}")
        
        if not user_id:
            return jsonify({'success': False, 'message': 'User ID is required'})
        
        if db.update_user_permissions(user_id, permissions):
            app.logger.info(f"✅ User {user_id} permissions updated successfully")
            return jsonify({'success': True, 'message': 'User permissions updated successfully'})
        else:
            app.logger.error(f"❌ Failed to update user {user_id} permissions")
            return jsonify({'success': False, 'message': 'Failed to update user permissions'})
            
    except Exception as e:
        app.logger.error(f"Error updating user: {str(e)}")
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/api/get_my_permissions')
@require_auth
def get_my_permissions():
    """Get current user's permissions"""
    try:
        user_id = session.get('user_id')
        
        # Get user role first
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT role FROM users WHERE id = ?', (user_id,))
        user_result = cursor.fetchone()
        conn.close()
        
        if user_result and user_result['role'] == 'Admin':
            # Admin gets all permissions
            permissions = {
                'purchase_requisition': True,
                'purchase_order': True,
                'check_status': True,
                'upload_po': True,
                'retrieve_po': True,
                'replace_amend_po': True,
                'vendor_lookup': True,
                'is_admin': True
            }
        else:
            # Regular user gets database permissions
            raw_permissions = db.get_user_permissions(user_id)
            # Convert integer values (0/1) to boolean values
            permissions = {}
            for key, value in raw_permissions.items():
                permissions[key] = bool(value) if value is not None else False
            permissions['is_admin'] = False
        
        app.logger.info(f"User {user_id} permissions: {permissions}")
        return jsonify({'success': True, 'permissions': permissions})
    except Exception as e:
        app.logger.error(f"Error getting permissions for user {user_id}: {e}")
        return jsonify({'success': False, 'error': str(e)})

# Test endpoint for debugging
@app.route('/test_project_generation', methods=['GET'])
def test_project_generation():
    """Test endpoint to verify project generation logic"""
    try:
        # Test data
        test_data = {
            'proj_code': 'I',
            'year': '2024',
            'client_code': '01',
            'sector_code': '01',
            'project_name': 'Test Project'
        }
        
        prefix = f"{test_data['proj_code']}{test_data['year']}{test_data['client_code']}{test_data['sector_code']}"
        
        # Load existing data
        try:
            dfp = pd.read_excel(DATA_FILE, dtype=str).fillna('')
        except FileNotFoundError:
            dfp = pd.DataFrame(columns=['Project Number', 'Project Name'])
        
        # Ensure required columns exist
        if 'Project Number' not in dfp.columns:
            dfp['Project Number'] = ''
        if 'Project Name' not in dfp.columns:
            dfp['Project Name'] = ''
        
        # Filter existing project numbers
        existing = dfp[dfp['Project Number'].str.startswith(prefix, na=False)]['Project Number']
        
        if not existing.empty:
            try:
                seqs = existing.str[-3:].astype(int)
                next_seq = seqs.max() + 1
            except:
                next_seq = 1
        else:
            next_seq = 1
            
        project_number = f"{prefix}{next_seq:03d}"
        
        return jsonify({
            'status': 'success',
            'test_data': test_data,
            'prefix': prefix,
            'existing_projects': existing.tolist(),
            'next_seq': next_seq,
            'generated_number': project_number,
            'data_file_exists': os.path.exists(DATA_FILE),
            'data_file_path': DATA_FILE
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ─── Upload PO Document ───────────────────────────────────────────────────────
@app.route('/upload_PO', methods=['POST'])
@require_auth
def upload_PO():
    po = sanitize_input(request.form.get('PO_number', ''))
    file = request.files.get('file')
    
    # Validate file upload
    is_valid, message = validate_file_upload(file)
    if not is_valid:
        return jsonify({'message': message}), 400
        
    if file and allowed_file(file.filename):
        df = pd.read_excel(EXCEL_FILE)
        df['PO Number'] = df['PO Number'].astype(str).str.strip()
        if 'File Path' not in df.columns:
            df['File Path'] = ''
        if po not in df['PO Number'].values:
            return jsonify({'message': 'PO not found.'}), 404
        existing = df.loc[df['PO Number']==po, 'File Path'].iloc[0]
        if pd.notna(existing) and existing:
            return jsonify({'message': 'Document already exists; use Replace.'})
        fn = secure_filename(file.filename)
        path = os.path.join(UPLOAD_FOLDER, f"{po}_{fn}")
        file.save(path)
        df.loc[df['PO Number']==po, 'File Path'] = path
        df.to_excel(EXCEL_FILE, index=False)

        # ─── Notify: PO Uploaded ───────────────────────────────────────
        add_notification(
            "fas fa-upload",
            "Purchase Order Document Uploaded",
            po
        )
        return jsonify({'message': 'Uploaded successfully.'})
    return jsonify({'message': 'Invalid file.'}), 400

# ─── Retrieve PO Document ─────────────────────────────────────────────────────
@app.route('/retrieve_PO', methods=['POST'])
@require_auth
def retrieve_PO():
    po = sanitize_input(request.form.get('PO_number', ''))
    df = pd.read_excel(EXCEL_FILE)
    df['PO Number'] = df['PO Number'].astype(str).str.strip()
    if po not in df['PO Number'].values:
        return jsonify({'message': 'PO not found.'}), 404
    path = df.loc[df['PO Number']==po, 'File Path'].iloc[0]
    if not path or not os.path.exists(path):
        return jsonify({'message': 'No document uploaded.'}), 404
    return send_from_directory(UPLOAD_FOLDER, os.path.basename(path), as_attachment=True)

# ─── Replace PO Document ──────────────────────────────────────────────────────
@app.route('/replace_PO', methods=['POST'])
@require_auth
def replace_PO():
    po = sanitize_input(request.form.get('PO_number', ''))
    file = request.files.get('file')
    
    # Validate file upload
    is_valid, message = validate_file_upload(file)
    if not is_valid:
        return jsonify({'message': message}), 400
        
    if file and allowed_file(file.filename):
        df = pd.read_excel(EXCEL_FILE)
        df['PO Number'] = df['PO Number'].astype(str).str.strip()
        if 'File Path' not in df.columns:
            df['File Path'] = ''
        if po not in df['PO Number'].values:
            return jsonify({'message': 'PO not found.'}), 404
        old = df.loc[df['PO Number']==po, 'File Path'].iloc[0]
        if old and os.path.exists(old):
            os.remove(old)
        fn = secure_filename(file.filename)
        path = os.path.join(UPLOAD_FOLDER, f"{po}_{fn}")
        file.save(path)
        df.loc[df['PO Number']==po, 'File Path'] = path
        df.to_excel(EXCEL_FILE, index=False)

        # ─── Notify: PO Amended ────────────────────────────────────────
        add_notification(
            "fas fa-edit",
            "PO Document Amended/Replaced",
            po
        )
        return jsonify({'message': 'Replaced successfully.'})
    return jsonify({'message': 'Invalid file.'}), 400

# ─── Live Notifications Endpoint ─────────────────────────────────────────────
@app.route('/notifications', methods=['GET'])
@require_auth
def notifications():
    """Return recent persistent system notifications (fallback to memory)."""
    try:
        system_notes = db.get_recent_system_notifications(limit=10)
        if system_notes:
            return jsonify(notifications=system_notes)
    except Exception as e:
        app.logger.error(f"Error loading system notifications: {e}")
    return jsonify(notifications=notifications_store[:10])

@app.route('/generate_form', methods=['GET','POST'])
@require_auth
def generate_form():
    form = request.form.to_dict()
    ctx = {k: form.get(k, '') for k in FIELDS}

    # Helper to surface errors as notifications that persist after refresh
    def notify_error(message: str):
        try:
            add_notification('fas fa-exclamation-circle', f"Error: {message}", url_for('po_system'))
        except Exception:
            pass
        # Queue a persistent flash to survive multiple immediate reloads
        session['pending_flash'] = {'category': 'error', 'message': message, 'remaining': 2}
        flash(message, 'error')

    pr_number = form.get('pr_number', '').strip()
    if not pr_number:
        notify_error("Please select a Purchase Request before generating a PO.")
        return redirect(url_for('po_system'))

    df_pr = pd.read_excel(DATA_FILE, dtype=str).fillna('')
    df_pr['PR Number'] = df_pr['PR Number'].str.strip()
    
    # Debug: Show available PRs and their Order Types
    app.logger.info(f"[PO Generation] Available PRs for PO generation:")
    available_prs = df_pr[df_pr['PR Status'].str.lower() == 'approved']
    for _, pr in available_prs.iterrows():
        order_type = pr.get('Order Type', 'N/A')
        app.logger.info(f"[PO Generation] - PR {pr['PR Number']}: Order Type = '{order_type}', Status = '{pr['PR Status']}'")
    
    pr_row_df = df_pr[df_pr['PR Number'] == pr_number]
    if pr_row_df.empty:
        notify_error(f"Purchase Request {pr_number} not found.")
        return redirect(url_for('po_system'))
    
    pr_row = pr_row_df.iloc[0]
    discipline = pr_row['Discipline'].strip()
    # NEW: Get department name from PR for budget checks
    department_name = pr_row['Requisition Department'].strip()
    # NEW: Get order type from PR for budget selection
    raw_order_type = pr_row.get('Order Type', '')
    app.logger.info(f"[PO Generation] Raw Order Type from PR: '{raw_order_type}' (type: {type(raw_order_type)})")
    
    # Handle NaN and empty values properly
    if pd.isna(raw_order_type) or str(raw_order_type).strip() == '':
        app.logger.warning(f"[PO Generation] Order Type is NaN or empty, defaulting to 'Material'")
        order_type = 'Material'
    else:
        order_type = str(raw_order_type).strip()
        app.logger.info(f"[PO Generation] Order Type processed: '{order_type}'")
    
    # NEW: Get item type from PR for NFA requirement check
    raw_item_type = pr_row.get('Item Type', '')
    app.logger.info(f"[PO Generation] Raw Item Type from PR: '{raw_item_type}' (type: {type(raw_item_type)})")
    
    # Handle NaN and empty values properly
    if pd.isna(raw_item_type) or str(raw_item_type).strip() == '':
        app.logger.warning(f"[PO Generation] Item Type is NaN or empty, defaulting to 'Budgeted'")
        item_type = 'Budgeted'
    else:
        item_type = str(raw_item_type).strip()
        app.logger.info(f"[PO Generation] Item Type processed: '{item_type}'")
    
    # Debug logging
    app.logger.info(f"[PO Generation] PR {pr_number} data:")
    app.logger.info(f"[PO Generation] - Discipline: '{discipline}'")
    app.logger.info(f"[PO Generation] - Department: '{department_name}'")
    app.logger.info(f"[PO Generation] - Order Type: '{order_type}'")
    app.logger.info(f"[PO Generation] - Available PR columns: {list(pr_row.index)}")
    
    # Check if Order Type column exists and what its value is
    if 'Order Type' in pr_row.index:
        app.logger.info(f"[PO Generation] - Order Type column found with value: '{pr_row['Order Type']}'")
    else:
        app.logger.info(f"[PO Generation] - Order Type column NOT found!")
        app.logger.info(f"[PO Generation] - Looking for similar columns...")
        for col in pr_row.index:
            if 'order' in col.lower() or 'type' in col.lower():
                app.logger.info(f"[PO Generation] - Similar column found: '{col}' = '{pr_row[col]}'")
    
    # Log the entire PR row for debugging
    app.logger.info(f"[PO Generation] - Full PR row data: {dict(pr_row)}")

    po_requester_role  = form.get('po_requester_role', '').strip()
    po_requester_email = form.get('po_requester_email', '').strip().lower()

    if not po_requester_role or not po_requester_email:
        notify_error("Please provide both Requester Role and Email.")
        return redirect(url_for('po_system'))

    # ─── 1) Calculate monetary values from the form ────────────────────────────
    pf   = float(form.get("pf_rate",   "0").strip("%") or 0)
    gstp = float(form.get("gst_rate",  "0").strip("%") or 0)
    fr   = float(form.get("freight_rate","0").strip("%") or 0)
    ot   = float(form.get("other_rate",  "0").strip("%") or 0)

    n_items   = int(form.get("number_of_items", "0") or 0)
    items     = []
    basic_amt = 0.0

    for i in range(1, n_items + 1):
        qty_str  = form.get(f"item_{i}_quantity", "0").replace(',', '')
        rate_str = form.get(f"item_{i}_unit_rate", "0").replace(',', '')
        item_name = form.get(f"item_{i}_name", "").strip()
        
        # Skip empty items (no name or zero quantity/rate)
        if not item_name or (not qty_str or qty_str == "0") or (not rate_str or rate_str == "0"):
            continue
            
        try:
            qty  = float(qty_str or 0)
            rate = float(rate_str or 0)
        except ValueError:
            flash("Invalid quantity/rate for one of the items. Please check that all quantities and rates are valid numbers.", 'error')
            return redirect(url_for('po_system'))

        total_line = qty * rate
        basic_amt  += total_line
        item_data = {
            "name":            item_name,
            "quantity":        qty,
            "unit_rate":       rate,
            "uom":             form.get(f"item_{i}_uom", "").strip(),
            "additional_info": form.get(f"item_{i}_additional_info", "").strip(),
            "amount":          f"{total_line:.2f}"
        }
        items.append(item_data)

    pf_amt  = basic_amt * (pf / 100.0)
    gst_amt = basic_amt * (gstp / 100.0)
    fr_amt  = basic_amt * (fr / 100.0)
    oth_amt = basic_amt * (ot / 100.0)
    total_po = basic_amt + pf_amt + gst_amt + fr_amt + oth_amt

    # ─── 2) VALIDATE AGAINST RULES (BASED ON BASIC_AMT) ────────────────────────
    t = basic_amt  # CRITICAL CHANGE: Use basic_amt for validation, not total_po

    # Case A: discipline == Engineering
    if discipline.lower() == 'engineering':
        if t < 1_000_000:
            if po_requester_role not in ("Head of Project Planning and Control", "Head of Engineering"):
                notify_error("❌ Authorization Error: Only Head of Project Planning & Control or Head of Engineering may generate a PO for Engineering when Indicative Price < ₹10 Lakh.")
                return redirect(url_for('po_system'))
            first_approver, second_approver = "Head of Procurement", "CFO"
        elif 1_000_000 <= t < 100_000_0000:
            if po_requester_role not in ("Head of Engineering", "CFO"):
                notify_error("❌ Authorization Error: Only Head of Engineering or CFO may generate a PO for Engineering when ₹10 Lakh ≤ Indicative Price < ₹10 Crore.")
                return redirect(url_for('po_system'))
            first_approver, second_approver = "CEO", None
        else:
            if po_requester_role not in ("CEO", "CFO"):
                notify_error("Only CEO or CFO may generate a PO for Engineering when Indicative Price ≥ ₹10 Crore.")
                return redirect(url_for('po_system'))
            first_approver, second_approver = "Chairman", None
    # Case B: discipline == Procurement
    elif discipline.lower() == 'procurement':
        if t < 2_500_000:
            if po_requester_role not in ("Head of Project Planning and Control", "Site Head Mechanical"):
                notify_error("Only HPPC or Site Head Mechanical may generate a PO for Procurement when Indicative Price < ₹25 Lakh.")
                return redirect(url_for('po_system'))
            first_approver, second_approver = "Head of Procurement", "CFO"
        else:
            if po_requester_role not in ("Head of Procurement", "CFO"):
                notify_error("Only Head of Procurement or CFO may generate a PO for Procurement when Indicative Price ≥ ₹25 Lakh.")
                return redirect(url_for('po_system'))
            first_approver, second_approver = "CEO", None
    # Case C: discipline == Construction
    elif discipline.lower() == 'construction':
        if t < 100_000:
            if po_requester_role not in ("Head of Project Planning and Control", "Head of Engineering"):
                notify_error("Only HPPC or Head of Engineering may generate a PO for Construction when Indicative Price < ₹1 Lakh.")
                return redirect(url_for('po_system'))
            first_approver, second_approver = "Head of Procurement", None
        elif 100_000 <= t < 1_000_000:
            if po_requester_role not in ("Head of Project Planning and Control", "Head of Engineering"):
                notify_error("Only HPPC or Head of Engineering may generate a PO for Construction when ₹1 Lakh ≤ Indicative Price < ₹10 Lakh.")
                return redirect(url_for('po_system'))
            first_approver, second_approver = "Head of Procurement", "CFO"
        elif 1_000_000 <= t < 25_000_000:
            if po_requester_role not in ("CFO", "Head of Procurement"):
                notify_error("Only CFO or Head of Procurement may generate a PO for Construction when ₹10 Lakh ≤ Indicative Price < ₹25 Crore.")
                return redirect(url_for('po_system'))
            first_approver, second_approver = "CEO", None
        else:
            if po_requester_role not in ("CFO", "CEO"):
                notify_error("Only CFO or CEO may generate a PO for Construction when Indicative Price ≥ ₹25 Crore.")
                return redirect(url_for('po_system'))
            first_approver, second_approver = "Chairman", None
    else:
        notify_error(f"Unknown discipline: {discipline}")
        return redirect(url_for('po_system'))

    # ─── 3) LOOK UP approver emails ───────────────────────────────────────────
    match_first = dept_email_df[dept_email_df['Department'].str.strip().str.lower() == first_approver.lower()]
    if match_first.empty:
        notify_error(f"❌ Configuration Error: No approver email found for {first_approver}. Please contact system administrator.")
        return redirect(url_for('po_system'))
    first_approver_email = match_first.iloc[0]['Email'].strip()

    second_approver_email = None
    if second_approver:
        match_second = dept_email_df[dept_email_df['Department'].str.strip().str.lower() == second_approver.lower()]
        if match_second.empty:
            notify_error(f"No approver email found for {second_approver}.")
            return redirect(url_for('po_system'))
        second_approver_email = match_second.iloc[0]['Email'].strip()

    # ─── 4) NFA FILE HANDLING ──────────────────────────────────────────────────
    nfa_file = request.files.get('nfa_file')
    nfa_filename = None
    
    # Check if NFA is required
    is_non_budgeted = item_type.lower() == 'non-budgeted'
    amount_to_deduct = basic_amt + fr_amt  # Indicative Price + Freight Charges
    
    # We'll check budget after loading it, but for now check if NFA file is provided when required
    if is_non_budgeted and (not nfa_file or not nfa_file.filename):
        notify_error("❌ Document Required: NFA document is required for Non-Budgeted items. Please upload the NFA document.")
        return redirect(url_for('po_system'))
    
    # Save NFA file if provided
    if nfa_file and nfa_file.filename:
        nfa_filename = secure_filename(nfa_file.filename)
        nfa_filename = f"{pr_number}_{nfa_filename}"
        nfa_file.save(os.path.join(UPLOAD_MRF, nfa_filename))  # Using same folder as Material Requisition Files
        app.logger.info(f"[PO Generation] NFA file saved: {nfa_filename}")
    
    # ─── 5) DEDUCT FROM BUDGET ─────────────────────────────────────────────────
    project_number = form.get('project_name', '').strip()
    app.logger.info(f"[PO Generation] Project number from form: '{project_number}'")
    
    # Check if project budget file exists
    project_budget_file = get_project_budget_file_path(project_number)
    app.logger.info(f"[PO Generation] Project budget file path: '{project_budget_file}'")
    
    df_budgets = load_project_budgets_for_pr(project_number)

    if df_budgets.empty:
        notify_error(f"❌ Budget Error: Budget information for project {project_number} could not be loaded. Please check if the budget file exists.")
        return redirect(url_for('po_system'))

    # Debug: Log the budget file structure
    app.logger.info(f"[PO Generation] Budget file structure:")
    app.logger.info(f"[PO Generation] Columns: {list(df_budgets.columns)}")
    app.logger.info(f"[PO Generation] Shape: {df_budgets.shape}")
    app.logger.info(f"[PO Generation] Sample data:")
    for idx, row in df_budgets.head().iterrows():
        app.logger.info(f"[PO Generation] Row {idx}: {dict(row)}")

    df_budgets.set_index('Department', inplace=True)

    if department_name not in df_budgets.index:
        flash(f"❌ Budget Error: Department '{department_name}' from PR not found in budgets sheet for project {project_number}. Please check the budget file.", 'error')
        return redirect(url_for('po_system'))

    # Select budget column based on order type
    app.logger.info(f"[PO Generation] Order Type from PR: '{order_type}', Department: '{department_name}'")
    app.logger.info(f"[PO Generation] Available budget columns: {list(df_budgets.columns)}")
    
    if order_type.lower() == 'services':
        budget_column = 'Service_Budget'
        app.logger.info(f"[PO Generation] Using Service_Budget column")
    else:
        budget_column = 'Material_Budget'  # Default to Material_Budget
        app.logger.info(f"[PO Generation] Using Material_Budget column")
    
    # Check if the budget column exists
    if budget_column not in df_budgets.columns:
        app.logger.error(f"[PO Generation] Budget column '{budget_column}' not found. Available columns: {list(df_budgets.columns)}")
        notify_error(f"❌ Budget Error: Budget column '{budget_column}' not found in project budget file. Please check the budget file structure.")
        return redirect(url_for('po_system'))
    
    current_budget = df_budgets.at[department_name, budget_column]
    app.logger.info(f"[PO Generation] Current {budget_column}: {current_budget}, Amount to deduct: {amount_to_deduct}")
    
    # Check if budget will be exceeded
    new_budget = current_budget - amount_to_deduct
    is_budget_exceeded = new_budget < 0
    
    # If budget is exceeded and NFA is not provided, require it
    if is_budget_exceeded and (not nfa_file or not nfa_file.filename):
        notify_error(f"❌ Budget Exceeded: Budget will be exceeded (Remaining: ₹{new_budget:.2f}). NFA document is required when budget exceeds limit. Please upload the NFA document.")
        return redirect(url_for('po_system'))
    
    app.logger.info(f"[PO Generation] Budget check - Current: {current_budget}, New: {new_budget}, Exceeded: {is_budget_exceeded}, NFA provided: {bool(nfa_file and nfa_file.filename)}")
    df_budgets.at[department_name, budget_column] = new_budget
    
    df_budgets.reset_index(inplace=True)
    project_budget_file = get_project_budget_file_path(project_number)
    if project_budget_file and os.path.exists(project_budget_file):
        df_budgets.to_excel(project_budget_file, index=False)
    else:
        flash(f"Warning: No project-specific budget file found for {project_number}. Budget changes are not saved.", "warning")


    # ─── 5) GENERATE DOCX, SAVE RECORD, and SEND EMAIL ────────────────────────
    new_po_number = get_next_PO_number(form['project_name'])
    ctx['po_number'] = new_po_number
    
    total_quantity = sum(item['quantity'] for item in items)
    
    # Add Special Conditions of Contract fields to context
    special_conditions = {}
    
    # Vendor Final Offer Date
    special_conditions['vendor_final_offer_date'] = form.get('vendor_final_offer_date', '')
    
    # Payment Milestones (collect all payment_milestone_X fields)
    payment_milestones = []
    for key, value in form.items():
        if key.startswith('payment_milestone_') and value and value.strip():
            payment_milestones.append(value.strip())
    special_conditions['payment_milestones'] = payment_milestones
    
    # Payment Documents
    special_conditions['payment_documents'] = form.get('payment_documents', '').strip()
    
    # Delivery Schedules (collect all delivery_schedule_X fields)
    delivery_schedules = []
    for key, value in form.items():
        if key.startswith('delivery_schedule_') and value and value.strip():
            delivery_schedules.append(value.strip())
    special_conditions['delivery_schedules'] = delivery_schedules
    
    # Add special conditions to context
    ctx.update(special_conditions)

    ctx.update({
        'items': items, 'total_quantity': total_quantity,
        'basic_amount': f"{basic_amt:.2f}", 'pf_charges': f"{pf_amt:.2f}",
        'freight_charges': f"{fr_amt:.2f}", 'other_charges': f"{oth_amt:.2f}",
        'gst_amt': f"{gst_amt:.2f}", 'total_po_amount': f"{total_po:.2f}",
        'total_amount': f"{total_po:.2f}"
    })

    tpl = DocxTemplate(os.path.join(BASE_DIR, 'template.docx'))
    tpl.render(ctx)
    buf = io.BytesIO()
    tpl.save(buf)
    buf.seek(0)
    
    filename = f"{new_po_number}.docx"
    save_path = os.path.join(PURCHASE_ORDER_FOLDER, filename)
    with open(save_path, "wb") as f:
        f.write(buf.read())

    df_po = pd.read_excel(EXCEL_FILE, dtype=str).fillna('')
    
    # Create rows for each item (one row per item with all PO details)
    new_rows = []
    for i, item in enumerate(items, 1):
        new_row = {
            "Date": datetime.now().strftime("%Y-%m-%d"), 
            "PO Number": new_po_number,
            "PR Number": pr_number, 
            "Project Number": pr_row['Project Number'],
            "Project Name": pr_row['Project Name'], 
            "Company Name": form.get("company", "").strip(),
            "Basic Amount": f"{basic_amt:.2f}",
            "PF Charges": f"{pf_amt:.2f}",
            "Freight Charges": f"{fr_amt:.2f}",
            "GST Amount": f"{gst_amt:.2f}",
            "Other Charges": f"{oth_amt:.2f}",
            "Total Amount": f"{total_po:.2f}", 
            "File Path": "", 
            "PO Status": "Pending",
            # Save all form fields except vendor details (only save Vendor Code)
            "Vendor Code": form.get("vendor_code", "").strip(),
            "PO Requester Role": form.get("po_requester_role", "").strip(),
            "PO Requester Email": form.get("po_requester_email", "").strip(),
            "PO Date": form.get("po_date", "").strip(),
            "Delivery Date": form.get("delivery_date", "").strip(),
            "Your Reference": form.get("your_reference", "").strip(),
            "Price Basis": form.get("price_basis", "").strip(),
            "Payment Terms": form.get("payment_term", "").strip(),
            "Ship To Location": form.get("ship_to_location", "").strip(),
            "Ship To Address": form.get("ship_to_address", "").strip(),
            "Ship To GSTIN": form.get("ship_to_gstin", "").strip(),
            "Bill To Company": form.get("bill_to_company", "").strip(),
            "Bill To Address": form.get("bill_to_address", "").strip(),
            "Bill To GSTIN": form.get("bill_to_gstin", "").strip(),
            "PF Rate": form.get("pf_rate", "0").strip(),
            "GST Rate": form.get("gst_rate", "0").strip(),
            "Freight Rate": form.get("freight_rate", "0").strip(),
            "Other Rate": form.get("other_rate", "0").strip(),
            "Number of Items": form.get("number_of_items", "1").strip(),
            # Item-specific fields
            "Item Name": item.get("name", ""),
            "Additional Info": item.get("additional_info", ""),
            "Quantity": item.get("quantity", ""),
            "UOM": item.get("uom", ""),
            "Unit Rate": item.get("unit_rate", "")
        }
        new_rows.append(new_row)
    
    df_po = pd.concat([df_po, pd.DataFrame(new_rows)], ignore_index=True)
    df_po.to_excel(EXCEL_FILE, index=False)

    # ─── 6) SAVE VENDOR DETAILS TO vendor_items.xlsx ────────────────────────────
    try:
        # Get vendor details from form
        vendor_code = form.get("vendor_code", "").strip()
        company_name = form.get("company", "").strip()
        vendor_address = form.get("company_address", "").strip()  # Fixed field name
        gst_number = form.get("gst", "").strip()
        contact_person = form.get("contact_person_name", "").strip()
        contact_mobile = form.get("contact_person_mobile", "").strip()
        contact_email = form.get("contact_person_email", "").strip()
        
        app.logger.info(f"[PO Generation] Vendor details check - vendor_code: '{vendor_code}', company_name: '{company_name}'")
        
        if vendor_code and company_name:  # Only save if we have vendor code and company name
            app.logger.info(f"[PO Generation] Saving vendor details: {vendor_code} - {company_name}")
            
            # Load existing vendor_items.xlsx or create new one
            try:
                df_vendor = pd.read_excel(VENDOR_FILE, dtype=str, engine='openpyxl')
            except FileNotFoundError:
                # Create new vendor_items.xlsx with proper structure
                df_vendor = pd.DataFrame(columns=[
                    'Vendor Code', 'Company Name', 'Vendor Address', 'GST Number',
                    'Contact Person', 'Contact Mobile', 'Contact Email',
                    'Item Name', 'Additional Info', 'Date Added'
                ])
            except Exception as e:
                app.logger.error(f"[PO Generation] Error reading vendor_items.xlsx: {e}")
                df_vendor = pd.DataFrame(columns=[
                    'Vendor Code', 'Company Name', 'Vendor Address', 'GST Number',
                    'Contact Person', 'Contact Mobile', 'Contact Email',
                    'Item Name', 'Additional Info', 'Date Added'
                ])
            
            # Check if vendor already exists
            existing_vendor_rows = df_vendor[df_vendor['Vendor Code'] == vendor_code]
            
            if not existing_vendor_rows.empty:
                # Vendor exists - update vendor details and add new items
                app.logger.info(f"[PO Generation] Vendor {vendor_code} already exists. Updating vendor details and adding new items.")
                
                # Remove existing vendor rows (to replace vendor details)
                df_vendor = df_vendor[df_vendor['Vendor Code'] != vendor_code]
                
                # Get existing items to preserve them (filter out nan/empty items)
                existing_items = existing_vendor_rows[['Item Name', 'Additional Info']].to_dict('records')
                
                # Filter out existing items with nan/empty names
                valid_existing_items = []
                for item in existing_items:
                    # Safely convert to string and strip
                    item_name_raw = item['Item Name']
                    if pd.isna(item_name_raw):
                        item_name = ''
                    else:
                        item_name = str(item_name_raw).strip()
                    
                    if item_name and item_name.lower() not in ['nan', 'none', 'null', '']:
                        valid_existing_items.append(item)
                
                app.logger.info(f"[PO Generation] Found {len(existing_items)} total existing items, {len(valid_existing_items)} valid items for vendor {vendor_code}")
                
                # Create new rows with updated vendor details for valid existing items
                current_date = datetime.now().strftime("%Y-%m-%d")
                updated_vendor_rows = []
                
                # Add valid existing items with updated vendor details
                for i, existing_item in enumerate(valid_existing_items, 1):
                    # Safely convert existing item data to strings
                    existing_item_name = str(existing_item['Item Name']).strip() if existing_item['Item Name'] else ''
                    existing_additional_info = str(existing_item['Additional Info']).strip() if existing_item['Additional Info'] else ''
                    
                    # Remove existing numbering prefix if present (e.g., "[1] Item Name" -> "Item Name")
                    if existing_item_name.startswith('[') and '] ' in existing_item_name:
                        existing_item_name = existing_item_name.split('] ', 1)[1]
                    
                    updated_vendor_rows.append({
                        'Vendor Code': vendor_code,
                        'Company Name': company_name,
                        'Vendor Address': vendor_address,
                        'GST Number': gst_number,
                        'Contact Person': contact_person,
                        'Contact Mobile': contact_mobile,
                        'Contact Email': contact_email,
                        'Item Name': f"[{i}] {existing_item_name}",
                        'Additional Info': existing_additional_info,
                        'Date Added': current_date
                    })
                
                # If no valid existing items, start new items from [1], otherwise continue numbering
                if len(valid_existing_items) == 0:
                    app.logger.info(f"[PO Generation] No valid existing items found for vendor {vendor_code}. Starting new items from [1]")
                
                # Add new items from current form (skip items with nan/empty names)
                item_counter = len(valid_existing_items) + 1
                app.logger.info(f"[PO Generation] Processing {len(items)} items for vendor {vendor_code}")
                for item in items:
                    # Safely convert item name to string
                    item_name_raw = item['name']
                    if pd.isna(item_name_raw):
                        item_name = ''
                    else:
                        item_name = str(item_name_raw).strip()
                    
                    # Skip items with nan, empty, or invalid item names
                    if not item_name or item_name.lower() in ['nan', 'none', 'null', '']:
                        app.logger.warning(f"[PO Generation] Skipping item with invalid name: {item_name}")
                        continue
                    
                    updated_vendor_rows.append({
                        'Vendor Code': vendor_code,
                        'Company Name': company_name,
                        'Vendor Address': vendor_address,
                        'GST Number': gst_number,
                        'Contact Person': contact_person,
                        'Contact Mobile': contact_mobile,
                        'Contact Email': contact_email,
                        'Item Name': f"[{item_counter}] {item_name}",
                        'Additional Info': str(item['additional_info']).strip() if item['additional_info'] else '',
                        'Date Added': current_date
                    })
                    app.logger.info(f"[PO Generation] Added item [{item_counter}] {item_name} for vendor {vendor_code}")
                    item_counter += 1
                
                # Add updated rows to vendor dataframe
                df_vendor = pd.concat([df_vendor, pd.DataFrame(updated_vendor_rows)], ignore_index=True)
                app.logger.info(f"[PO Generation] Updated vendor {vendor_code} with {len(valid_existing_items)} valid existing + {len(items)} new items")
                
            else:
                # New vendor - add all items normally
                app.logger.info(f"[PO Generation] New vendor {vendor_code}. Adding all items.")
                current_date = datetime.now().strftime("%Y-%m-%d")
                new_vendor_rows = []
                
                item_counter = 1
                app.logger.info(f"[PO Generation] Processing {len(items)} items for new vendor {vendor_code}")
                for item in items:
                    # Safely convert item name to string
                    item_name_raw = item['name']
                    if pd.isna(item_name_raw):
                        item_name = ''
                    else:
                        item_name = str(item_name_raw).strip()
                    
                    # Skip items with nan, empty, or invalid item names
                    if not item_name or item_name.lower() in ['nan', 'none', 'null', '']:
                        app.logger.warning(f"[PO Generation] Skipping item with invalid name: {item_name}")
                        continue
                    
                    new_vendor_rows.append({
                        'Vendor Code': vendor_code,
                        'Company Name': company_name,
                        'Vendor Address': vendor_address,
                        'GST Number': gst_number,
                        'Contact Person': contact_person,
                        'Contact Mobile': contact_mobile,
                        'Contact Email': contact_email,
                        'Item Name': f"[{item_counter}] {item_name}",
                        'Additional Info': str(item['additional_info']).strip() if item['additional_info'] else '',
                        'Date Added': current_date
                    })
                    app.logger.info(f"[PO Generation] Added item [{item_counter}] {item_name} for new vendor {vendor_code}")
                    item_counter += 1
                
                # Add new rows to vendor dataframe
                df_vendor = pd.concat([df_vendor, pd.DataFrame(new_vendor_rows)], ignore_index=True)
                app.logger.info(f"[PO Generation] Added new vendor {vendor_code} with {len(new_vendor_rows)} items")
            
            # Save back to vendor_items.xlsx
            df_vendor.to_excel(VENDOR_FILE, index=False)
            app.logger.info(f"[PO Generation] Saved vendor data to {VENDOR_FILE} - Total rows: {len(df_vendor)}")
        else:
            app.logger.warning(f"[PO Generation] Skipping vendor save - missing vendor_code or company_name")
            
    except Exception as e:
        app.logger.error(f"[PO Generation] Failed to save vendor details: {e}")
        # Don't fail the PO generation if vendor saving fails

    # Create approval URLs for first approver
    approve_url_1 = url_for('approval_page', type='po', action='approve', id=new_po_number, role=first_approver, _external=True, _scheme=app.config.get('PREFERRED_URL_SCHEME', 'https'))
    reject_url_1 = url_for('approval_page', type='po', action='reject', id=new_po_number, role=first_approver, _external=True, _scheme=app.config.get('PREFERRED_URL_SCHEME', 'https'))
    
    details_table = create_po_details_table(
        po_number=new_po_number, project_name=pr_row['Project Number'], pr_number=pr_number,
        company=form.get("company", "").strip(), total_amount=f"{total_po:,.2f}",
        basic_amount=f"{basic_amt:,.2f}", pf_amount=f"{pf_amt:,.2f}", gst_amount=f"{gst_amt:,.2f}",
        freight_amount=f"{fr_amt:,.2f}", other_amount=f"{oth_amt:,.2f}", items=items
    )
    content = f"<p>A new Purchase Order has been generated and requires your approval.</p><p><strong>⚠️ IMPORTANT:</strong> Click the button below to review and approve/reject this PO. Do not use email preview links.</p>"
    action_buttons = [{"text": "🔍 Review & Approve/Reject", "url": approve_url_1, "color": "primary"}]
    
    html_1 = create_modern_email_template(
        title="Purchase Order Approval Required", recipient_name=first_approver, content=content,
        action_buttons=action_buttons, details_table=details_table
    )

    try:
        send_email(po_requester_email, first_approver_email, f"Approval Needed: PO {new_po_number}", html_1)
    except Exception as e:
        flash("Failed to send approval email. Please check server logs.")

    # Store approval chain in database for persistence across email clicks
    approval_chain = {
        "first": {"role": first_approver, "email": first_approver_email},
        "second": None if not second_approver else {"role": second_approver, "email": second_approver_email},
        "requester_email": po_requester_email
    }
    
    # Store in session for immediate use
    session[f"po_chain_{new_po_number}"] = approval_chain
    
    # Also store in database for persistence
    try:
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Create approval_chains table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS approval_chains (
                po_number TEXT PRIMARY KEY,
                chain_data TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Store the chain data as JSON
        import json
        chain_json = json.dumps(approval_chain)
        cursor.execute('''
            INSERT OR REPLACE INTO approval_chains (po_number, chain_data)
            VALUES (?, ?)
        ''', (new_po_number, chain_json))
        
        conn.commit()
        conn.close()
        app.logger.info(f"Approval chain stored in database for PO {new_po_number}")
        
    except Exception as e:
        app.logger.error(f"Failed to store approval chain in database: {e}")
        # Continue with session storage as fallback

    # ─── 7) HANDLE ADDITIONAL DOCUMENTS UPLOAD ────────────────────────────────
    try:
        # Create additional documents folder for this PO
        additional_docs_folder = os.path.join(BASE_DIR, "additional_documents", new_po_number)
        os.makedirs(additional_docs_folder, exist_ok=True)
        
        # Handle additional documents upload
        additional_docs_uploaded = []
        
        # Technical Specification - Approved MR Copy
        if 'tech_spec_file' in request.files:
            tech_spec_file = request.files['tech_spec_file']
            if tech_spec_file and tech_spec_file.filename:
                filename = secure_filename(tech_spec_file.filename)
                file_extension = os.path.splitext(filename)[1]
                new_filename = f"{new_po_number}-Technical_Specification-Approved_MR_Copy{file_extension}"
                file_path = os.path.join(additional_docs_folder, new_filename)
                tech_spec_file.save(file_path)
                additional_docs_uploaded.append(new_filename)
                app.logger.info(f"[PO Generation] Saved Technical Specification: {new_filename}")
        
        # Approved Price Comparative Sheet
        if 'price_comp_file' in request.files:
            price_comp_file = request.files['price_comp_file']
            if price_comp_file and price_comp_file.filename:
                filename = secure_filename(price_comp_file.filename)
                file_extension = os.path.splitext(filename)[1]
                new_filename = f"{new_po_number}-Approved_Price_Comparative_Sheet{file_extension}"
                file_path = os.path.join(additional_docs_folder, new_filename)
                price_comp_file.save(file_path)
                additional_docs_uploaded.append(new_filename)
                app.logger.info(f"[PO Generation] Saved Price Comparative Sheet: {new_filename}")
        
        # Approved NFA
        if 'nfa_doc_file' in request.files:
            nfa_doc_file = request.files['nfa_doc_file']
            if nfa_doc_file and nfa_doc_file.filename:
                filename = secure_filename(nfa_doc_file.filename)
                file_extension = os.path.splitext(filename)[1]
                new_filename = f"{new_po_number}-Approved_NFA{file_extension}"
                file_path = os.path.join(additional_docs_folder, new_filename)
                nfa_doc_file.save(file_path)
                additional_docs_uploaded.append(new_filename)
                app.logger.info(f"[PO Generation] Saved Approved NFA: {new_filename}")
        
        if additional_docs_uploaded:
            app.logger.info(f"[PO Generation] Successfully uploaded {len(additional_docs_uploaded)} additional documents for PO {new_po_number}")
        else:
            app.logger.info(f"[PO Generation] No additional documents uploaded for PO {new_po_number}")
            
    except Exception as e:
        app.logger.error(f"[PO Generation] Failed to handle additional documents for PO {new_po_number}: {e}")
        # Don't fail the PO generation if additional documents upload fails

    add_notification('fas fa-file-invoice', f'PO {new_po_number} created, pending approval from {first_approver}', new_po_number)
    
    # Queue success flash to persist across any immediate reloads
    session['pending_flash'] = {
        'category': 'success',
        'message': f"✅ Success! Purchase Order {new_po_number} has been created and sent for approval to {first_approver}.",
        'remaining': 2
    }
    flash(f"✅ Success! Purchase Order {new_po_number} has been created and sent for approval to {first_approver}.", 'success')
    return redirect(url_for('po_system'))
@app.route('/api/v1/pr-budgets', methods=['GET'])
def get_pr_budgets():
    """
    Get budget data for PR form - no API key required for internal use
    """
    project_number = request.args.get('project_number', '').strip()
    
    try:
        if project_number:
            # Load project-specific budgets
            df_budgets = load_project_budgets_for_pr(project_number)
        else:
            # Load general budgets
            df_budgets = load_project_budgets_for_pr(project_number)
        
        # Convert to the format expected by the frontend
        dynamic_budgets = {
            row['Department']: {
                'Material_Budget': float(row.get('Material_Budget', 0)),
                'Service_Budget': float(row.get('Service_Budget', 0))
            }
            for _, row in df_budgets.iterrows()
        }
        
        return jsonify(dynamic_budgets)
        
    except Exception as e:
        app.logger.error(f"Error getting PR budgets: {str(e)}")
        return jsonify({
            'error': 'Failed to get budget data',
            'message': str(e)
        }), 500

def process_po_approval(po, role, chain, df_po):
    """Process PO approval directly from email link"""
    try:
        # Load the chain info from session or database
        chain_key = f"po_chain_{po}"
        if chain_key not in session:
            # Try to load from database
            try:
                conn = db.get_connection()
                cursor = conn.cursor()
                
                cursor.execute('SELECT chain_data FROM approval_chains WHERE po_number = ?', (po,))
                result = cursor.fetchone()
                conn.close()
                
                if result:
                    import json
                    chain = json.loads(result[0])
                    app.logger.info(f"Loaded approval chain from database for PO {po}")
                else:
                    return render_template('approval_pages.html', 
                                        type='po', 
                                        action='approve', 
                                        id=po, 
                                        role=role,
                                        po_number=po,
                                        error="No approval chain found for this PO.")
            except Exception as e:
                app.logger.error(f"Failed to load approval chain from database: {e}")
                return render_template('approval_pages.html', 
                                    type='po', 
                                    action='approve', 
                                    id=po, 
                                    role=role,
                                    po_number=po,
                                    error="Error loading approval chain.")

        first_info = chain.get('first')
        second_info = chain.get('second')
        requester_email = chain.get('requester_email')

        # Identify which stage this approval belongs to
        is_first = (first_info and role.lower() == first_info['role'].lower())
        is_second = (second_info and role.lower() == second_info['role'].lower())

        if not (is_first or is_second):
            return render_template('approval_pages.html', 
                                type='po', 
                                action='approve', 
                                id=po, 
                                role=role,
                                po_number=po,
                                error=f"Role '{role}' is not a valid approver for PO {po}.")

        # Helper to update the PO_Status cell
        def set_po_status(new_status):
            df_po.loc[df_po['PO Number'] == po, 'PO Status'] = new_status
            df_po.to_excel(EXCEL_FILE, index=False)

        # ─── Stage 1 approval ──────────────────────────────────────────
        if is_first:
            if second_info:
                # There's a second approver, send to them
                set_po_status("First Approval Complete - Pending Second Approval")
                
                # Create approval URLs for second approver first
                approve_url_2 = url_for('approve_po', po=po, action='approve', role=second_info['role'], _external=True)
                reject_url_2 = url_for('approve_po', po=po, action='reject', role=second_info['role'], _external=True)
                
                action_buttons = [
                    {"text": "✅ Approve", "url": approve_url_2, "color": "primary"}, 
                    {"text": "❌ Reject", "url": reject_url_2, "color": "danger"}
                ]
                
                # Send email to second approver with full PO details
                subject = f"PO {po} requires your final approval"
                
                # Get PO details from Excel file
                df_po = pd.read_excel(EXCEL_FILE, dtype=str).fillna('')
                po_row = df_po[df_po['PO Number'] == po]
                
                if not po_row.empty:
                    po_data = po_row.iloc[0]
                    # Get PR details for additional context
                    df_pr = pd.read_excel(DATA_FILE, dtype=str).fillna('')
                    pr_row = df_pr[df_pr['PR Number'] == po_data['PR Number']]
                    
                    if not pr_row.empty:
                        pr_data = pr_row.iloc[0]
                        # Create detailed table for second approver
                        po_items = get_po_items_for_email(po)
                        details_table = create_po_details_table(
                            po_number=po, 
                            project_name=po_data['Project Number'], 
                            pr_number=po_data['PR Number'],
                            company=po_data['Company Name'], 
                            total_amount=po_data['Total Amount'],
                            basic_amount=po_data['Basic Amount'], 
                            pf_amount=po_data['PF Charges'], 
                            gst_amount=po_data['GST Amount'],
                            freight_amount=po_data['Freight Charges'], 
                            other_amount=po_data['Other Charges'], 
                            items=po_items
                        )
                        
                        content = f"""
                          <p>Purchase Order <strong>{po}</strong> has been approved by {first_info['role']} and now requires your final approval.</p>
                          <p>Please review the details below and take action.</p>
                        """
                        
                        html = create_modern_email_template(
                            title="PO Final Approval Required",
                            recipient_name=second_info['role'],
                            content=content,
                            action_buttons=action_buttons,
                            details_table=details_table,
                            footer_text="This is an automated notification from the Purchase Order Management System."
                        )
                    else:
                        # Fallback if PR data not found
                        content = f"""
                          <p>Purchase Order <strong>{po}</strong> has been approved by {first_info['role']} and now requires your final approval.</p>
                          <p>Please review and take action.</p>
                        """
                        
                        html = create_modern_email_template(
                            title="PO Final Approval Required",
                            recipient_name=second_info['role'],
                            content=content,
                            action_buttons=action_buttons,
                            footer_text="This is an automated notification from the Purchase Order Management System."
                        )
                else:
                    # Fallback if PO data not found
                    content = f"""
                      <p>Purchase Order <strong>{po}</strong> has been approved by {first_info['role']} and now requires your final approval.</p>
                      <p>Please review and take action.</p>
                    """
                    
                    html = create_modern_email_template(
                        title="PO Final Approval Required",
                        recipient_name=second_info['role'],
                        content=content,
                        action_buttons=action_buttons,
                        footer_text="This is an automated notification from the Purchase Order Management System."
                    )
                
                try:
                    send_email(first_info['email'], second_info['email'], subject, html)
                    app.logger.info(f"[PO {po}] second approval email sent to {second_info['email']}")
                except Exception as e:
                    app.logger.exception(f"[PO {po}] failed to send second approval email: {e}")
                
                # Redirect to approval page so UI JS can render details
                return redirect(url_for('approval_page', 
                                      type='po', 
                                      action='approve', 
                                      id=po, 
                                      role=role,
                                      po_number=po))
            else:
                # No second approver, PO is fully approved
                set_po_status("Approved")
                
                # Notify requester
                subject = f"Your PO {po} has been approved"
                content = f"""
                  <p>Your Purchase Order <strong>{po}</strong> has been <strong>fully approved</strong> by {first_info['role']}.</p>
                  <p>This PO is now ready for execution.</p>
                """
                
                html = create_modern_email_template(
                    title="PO Approved",
                    recipient_name="Requester",
                    content=content,
                    footer_text="This is an automated notification from the Purchase Order Management System."
                )
                
                try:
                    send_email(first_info['email'], requester_email, subject, html)
                    app.logger.info(f"[PO {po}] approval notification sent to {requester_email}")
                except Exception as e:
                    app.logger.exception(f"[PO {po}] failed to notify requester on approval: {e}")
                
                # Cleanup chain
                session.pop(chain_key, None)
                
                # Redirect to approval page so UI JS can render details
                return redirect(url_for('approval_page', 
                                      type='po', 
                                      action='approve', 
                                      id=po, 
                                      role=role,
                                      po_number=po))

        # ─── Stage 2 approval ──────────────────────────────────────────
        elif is_second:
            # Final approval
            set_po_status("Approved")
            
            # Notify requester
            subject = f"Your PO {po} has been fully approved"
            content = f"""
              <p>Your Purchase Order <strong>{po}</strong> has been <strong>fully approved</strong> by both {first_info['role']} and {second_info['role']}.</p>
              <p>This PO is now ready for execution.</p>
            """
            
            html = create_modern_email_template(
                title="PO Fully Approved",
                recipient_name="Requester",
                content=content,
                footer_text="This is an automated notification from the Purchase Order Management System."
            )
            
            try:
                send_email(second_info['email'], requester_email, subject, html)
                app.logger.info(f"[PO {po}] final approval notification sent to {requester_email}")
            except Exception as e:
                app.logger.exception(f"[PO {po}] failed to notify requester on final approval: {e}")
            
            # Also notify first approver
            try:
                notify_first_approver_subject = f"PO {po} has been fully approved"
                notify_first_approver_content = f"""
                  <p>The Purchase Order {po} that you approved has been <strong>Fully Approved</strong> by {second_info['role']}.</p>
                  <p>This PO is now ready for execution.</p>
                """
                
                html_first = create_modern_email_template(
                    title="PO Fully Approved",
                    recipient_name=first_info['role'],
                    content=notify_first_approver_content
                )
                
                send_email(second_info['email'], first_info['email'], notify_first_approver_subject, html_first)
                app.logger.info(f"[PO {po}] first approver notified of full approval")
            except Exception as e:
                app.logger.exception(f"[PO {po}] failed to notify first approver of full approval: {e}")
            
            # Cleanup chain
            session.pop(chain_key, None)
            
            # Redirect to approval page so UI JS can render details
            return redirect(url_for('approval_page', 
                                  type='po', 
                                  action='approve', 
                                  id=po, 
                                  role=role,
                                  po_number=po))

    except Exception as e:
        app.logger.exception(f"[PO {po}] Error processing approval: {e}")
        return redirect(url_for('approval_page', 
                              type='po', 
                              action='approve', 
                              id=po, 
                              role=role,
                              po_number=po,
                              error=f"Error processing approval: {str(e)}"))

def process_po_rejection(po, role, chain, df_po):
    """Process PO rejection directly from email link"""
    try:
        # Load the chain info from session
        chain_key = f"po_chain_{po}"
        if chain_key not in session:
            return render_template('approval_pages.html', 
                                type='po', 
                                action='reject', 
                                id=po, 
                                role=role,
                                po_number=po,
                                error="No approval chain found for this PO.")

        first_info = chain.get('first')
        second_info = chain.get('second')
        requester_email = chain.get('requester_email')

        # Identify which stage this rejection belongs to
        is_first = (first_info and role.lower() == first_info['role'].lower())
        is_second = (second_info and role.lower() == second_info['role'].lower())

        if not (is_first or is_second):
            return render_template('approval_pages.html', 
                                type='po', 
                                action='reject', 
                                id=po, 
                                role=role,
                                po_number=po,
                                error=f"Role '{role}' is not a valid approver for PO {po}.")

        # Read current status to avoid double-crediting budgets
        current_status = None
        try:
            current_status = df_po.loc[df_po['PO Number'] == po, 'PO Status'].iloc[0]
        except Exception:
            current_status = None

        # Credit budget back if this is the first time moving to Rejected
        # Check if budget was deducted during PO creation (Basic Amount > 0) but not yet credited back
        po_row = df_po[df_po['PO Number'] == po].iloc[0]
        basic_amount = pd.to_numeric(po_row.get('Basic Amount', 0), errors='coerce') or 0
        
        # Credit budget if:
        # 1. PO is not currently rejected, OR
        # 2. PO is rejected but has a Basic Amount > 0 (meaning budget was deducted during creation)
        should_credit_budget = (
            (current_status or '').strip().lower() != 'rejected' or
            basic_amount > 0
        )
        
        if should_credit_budget:
            try:
                # Use PO details already loaded above
                pr_number = po_row.get('PR Number', '').strip()
                project_number = po_row.get('Project Number', '').strip()

                # Determine department and order type from PR
                df_pr = pd.read_excel(DATA_FILE, dtype=str).fillna('')
                pr_match = df_pr[df_pr['PR Number'] == pr_number]
                department_name = pr_match.iloc[0]['Requisition Department'].strip() if not pr_match.empty else ''
                pr_order_type_raw = pr_match.iloc[0].get('Order Type', '') if not pr_match.empty else ''
                pr_order_type = str(pr_order_type_raw).strip().lower() if pr_order_type_raw is not None else ''

                # Compute refund amount = Basic Amount + Freight Charges (as used during deduction)
                fr_amt = pd.to_numeric(po_row.get('Freight Charges', 0), errors='coerce') or 0
                amount_to_credit = float(basic_amount) + float(fr_amt)

                app.logger.info(f"[PO {po}] Refund check: dept='{department_name}', order_type='{pr_order_type}', project='{project_number}', credit={amount_to_credit}")

                # Load project-specific budgets and credit back
                if department_name and project_number:
                    df_budgets = load_project_budgets_for_pr(project_number)
                    if not df_budgets.empty and 'Department' in df_budgets.columns:
                        df_budgets.set_index('Department', inplace=True)
                        if department_name in df_budgets.index:
                            budget_column = 'Service_Budget' if pr_order_type == 'services' else 'Material_Budget'
                            if budget_column in df_budgets.columns:
                                current_budget = pd.to_numeric(df_budgets.at[department_name, budget_column], errors='coerce')
                                if pd.isna(current_budget):
                                    current_budget = 0
                                new_budget = float(current_budget) + amount_to_credit
                                df_budgets.at[department_name, budget_column] = new_budget
                                df_budgets.reset_index(inplace=True)
                                project_budget_file = get_project_budget_file_path(project_number)
                                if project_budget_file and os.path.exists(project_budget_file):
                                    df_budgets.to_excel(project_budget_file, index=False)
                                    app.logger.info(f"[PO {po}] Credited {amount_to_credit} back to {budget_column} for '{department_name}' (new={new_budget})")
                                    
                                    # Mark PO as budget refunded to prevent double-crediting
                                    df_po.loc[df_po['PO Number'] == po, 'Basic Amount'] = '0.00'
                                    df_po.to_excel(EXCEL_FILE, index=False)
                                    app.logger.info(f"[PO {po}] Marked Basic Amount as 0 to prevent double-crediting")
                                else:
                                    app.logger.warning(f"[PO {po}] Project budget file not found for {project_number}; refund not persisted")
                            else:
                                app.logger.error(f"[PO {po}] Budget column '{budget_column}' missing in budgets file")
                        else:
                            app.logger.error(f"[PO {po}] Department '{department_name}' not found in budgets file for project {project_number}")
                    else:
                        app.logger.error(f"[PO {po}] Budgets dataframe empty or missing 'Department' for project {project_number}")
                else:
                    app.logger.error(f"[PO {po}] Missing department or project number; cannot credit budget back")
            except Exception as budget_err:
                app.logger.exception(f"[PO {po}] Error crediting budget back on rejection: {budget_err}")

        # Update PO status to Rejected (idempotent)
        try:
            df_po.loc[df_po['PO Number'] == po, 'PO Status'] = 'Rejected'
            df_po.to_excel(EXCEL_FILE, index=False)
        except Exception as save_err:
            app.logger.exception(f"[PO {po}] Error saving PO status on rejection: {save_err}")
        
        # Notify requester
        subject = f"Your PO {po} was rejected"
        content = f"""
          <p>Your Purchase Order has been <strong>Rejected</strong>.</p>
          <p><strong>PO Number:</strong> <span class="amount-highlight">{po}</span></p>
          <p><strong>Rejected by:</strong> {role}</p>
          <p>Please contact the approver for more details.</p>
        """
        
        html = create_modern_email_template(
            title="Purchase Order Rejected",
            recipient_name="Requester",
            content=content,
            footer_text="This is an automated notification from the Purchase Order Management System."
        )
        
        try:
            send_email(first_info['email'], requester_email, subject, html)
            app.logger.info(f"[PO {po}] rejection notification sent to {requester_email}")
        except Exception as e:
            app.logger.exception(f"[PO {po}] failed to notify requester on rejection: {e}")

        # Cleanup chain
        session.pop(chain_key, None)
        
        # Redirect to approval page to show rejection form/feedback
        return redirect(url_for('approval_page', 
                              type='po', 
                              action='reject', 
                              id=po, 
                              role=role,
                              po_number=po))

    except Exception as e:
        app.logger.exception(f"[PO {po}] Error processing rejection: {e}")
        return redirect(url_for('approval_page', 
                              type='po', 
                              action='reject', 
                              id=po, 
                              role=role,
                              po_number=po,
                              error=f"Error processing rejection: {str(e)}"))

@app.route('/approve_po', methods=['GET', 'POST'])
def approve_po():
    # Get parameters from either GET args or POST form data
    po = sanitize_input(request.args.get('po') or request.form.get('po_number', '')).strip()
    action = sanitize_input(request.args.get('action') or request.form.get('action', '')).lower()   # "approve" or "reject"
    role = sanitize_input(request.args.get('role') or request.form.get('role', '')).strip()     # e.g. "Head of Procurement"
    
    # Rate limiting check
    if not check_rate_limit(request.remote_addr, f"po_{po}_{action}", limit_seconds=5):
        app.logger.warning(f"[PO APPROVAL DEBUG] Rate limited: {request.remote_addr} for PO {po} {action}")
        return jsonify({'success': False, 'message': 'Too many requests. Please wait a few seconds and try again.'}), 429

    # Add comprehensive logging
    app.logger.info(f"[PO APPROVAL DEBUG] Route accessed: po={po}, action={action}, role={role}, method={request.method}")
    app.logger.info(f"[PO APPROVAL DEBUG] Request headers: {dict(request.headers)}")
    app.logger.info(f"[PO APPROVAL DEBUG] Request args: {dict(request.args)}")
    app.logger.info(f"[PO APPROVAL DEBUG] Request form: {dict(request.form)}")
    app.logger.info(f"[PO APPROVAL DEBUG] User-Agent: {request.headers.get('User-Agent', 'Unknown')}")
    app.logger.info(f"[PO APPROVAL DEBUG] Remote address: {request.remote_addr}")

    if not po or action not in ('approve', 'reject') or not role:
        app.logger.warning(f"[PO APPROVAL DEBUG] Invalid parameters - returning error")
        return render_template('approval_pages.html', 
                            type='po', 
                            action='approve', 
                            id=po or 'N/A', 
                            role=role or 'N/A',
                            po_number=po or 'N/A',
                            error="Invalid request parameters")

    # Load current PO_data.xlsx
    df_po = pd.read_excel(EXCEL_FILE, dtype=str).fillna('')
    df_po['PO Number'] = df_po['PO Number'].str.strip()

    # Ensure the PO exists
    if po not in df_po['PO Number'].values:
        app.logger.error(f"[PO APPROVAL DEBUG] PO {po} not found in data")
        return redirect(url_for('approval_page', 
                              type='po', 
                              action='approve', 
                              id=po, 
                              role=role,
                              po_number=po,
                              error=f"PO {po} not found."))

    # Load the chain info from session or database
    chain_key = f"po_chain_{po}"
    if chain_key not in session:
        app.logger.info(f"[PO APPROVAL DEBUG] Chain not in session, loading from database")
        # Try to load from database
        try:
            conn = db.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('SELECT chain_data FROM approval_chains WHERE po_number = ?', (po,))
            result = cursor.fetchone()
            conn.close()
            
            if result:
                import json
                chain = json.loads(result[0])
                app.logger.info(f"[PO APPROVAL DEBUG] Loaded approval chain from database for PO {po}")
            else:
                app.logger.error(f"[PO APPROVAL DEBUG] No approval chain found in database for PO {po}")
                return redirect(url_for('approval_page', 
                                      type='po', 
                                      action='approve', 
                                      id=po, 
                                      role=role,
                                      error=f"No approval chain found for PO {po}."))
        except Exception as e:
            app.logger.error(f"[PO APPROVAL DEBUG] Failed to load approval chain from database: {e}")
            return redirect(url_for('approval_page', 
                                  type='po', 
                                  action='approve', 
                                  id=po, 
                                  role=role,
                                  error="Error loading approval chain."))
    else:
        app.logger.info(f"[PO APPROVAL DEBUG] Chain found in session for PO {po}")
        chain = session[chain_key]

    # If this is a GET request, process the approval directly and RETURN EARLY
    if request.method == 'GET':
        app.logger.info(f"[PO APPROVAL DEBUG] Processing GET request - calling processing function")
        # Process the approval/rejection directly from email link
        if action == 'approve':
            app.logger.info(f"[PO APPROVAL DEBUG] Calling process_po_approval for {po}")
            return process_po_approval(po, role, chain, df_po)
        elif action == 'reject':
            app.logger.info(f"[PO APPROVAL DEBUG] Calling process_po_rejection for {po}")
            return process_po_rejection(po, role, chain, df_po)
        else:
            app.logger.warning(f"[PO APPROVAL DEBUG] Invalid action: {action}")
            return redirect(url_for('approval_page', 
                                  type='po', 
                                  action='approve', 
                                  id=po, 
                                  role=role,
                                  error="Invalid action specified"))

    app.logger.info(f"[PO APPROVAL DEBUG] Processing POST request - continuing with main logic")
    # POST request logic continues here (for form submissions from approval page)
    first_info  = chain.get('first')   # {"role": "...", "email": "..."}
    second_info = chain.get('second')  # same structure or None
    requester_email = chain.get('requester_email')

    app.logger.info(f"[PO APPROVAL DEBUG] Chain info: first={first_info}, second={second_info}, requester={requester_email}")

    # Identify which stage this click belongs to
    # If role matches first_info['role'] → we're in stage1
    # If role matches second_info['role'] → we're in stage2
    is_first  = (first_info and role.lower() == first_info['role'].lower())
    is_second = (second_info and role.lower() == second_info['role'].lower())

    app.logger.info(f"[PO APPROVAL DEBUG] Stage identification: is_first={is_first}, is_second={is_second}")

    if not (is_first or is_second):
        app.logger.warning(f"[PO APPROVAL DEBUG] Role '{role}' not valid for PO {po}")
        return redirect(url_for('approval_page', 
                              type='po', 
                              action=action, 
                              id=po, 
                              role=role,
                              error=f"Role '{role}' is not a valid approver for PO {po}."))

    # Helper to update the PO_Status cell
    def set_po_status(new_status):
        df_po.loc[df_po['PO Number'] == po, 'PO Status'] = new_status
        df_po.to_excel(EXCEL_FILE, index=False)

    # ─── Stage 1 approval/rejection ──────────────────────────────────────────
    if is_first:
        app.logger.info(f"[PO APPROVAL DEBUG] Processing Stage 1 {action} for PO {po}")
        if action == 'reject':
            # Handle rejection with feedback if this is a POST request
            if request.method == 'POST':
                rejection_reason = sanitize_input(request.form.get('rejection_reason', ''))
                rejection_details = sanitize_input(request.form.get('rejection_details', ''))
                suggested_actions = sanitize_input(request.form.get('suggested_actions', ''))
                
                if not rejection_reason or not rejection_details:
                    return jsonify({'success': False, 'message': 'Rejection reason and details are required'}), 400
                
                app.logger.info(f"[PO APPROVAL DEBUG] Stage 1 rejection with feedback for PO {po}")
                
                # Credit budget back before marking as rejected
                try:
                    # Load PO details
                    po_row = df_po[df_po['PO Number'] == po].iloc[0]
                    pr_number = po_row.get('PR Number', '').strip()
                    project_number = po_row.get('Project Number', '').strip()
                    basic_amount = pd.to_numeric(po_row.get('Basic Amount', 0), errors='coerce') or 0
                    
                    if basic_amount > 0:  # Only credit if budget was deducted
                        # Determine department and order type from PR
                        df_pr = pd.read_excel(DATA_FILE, dtype=str).fillna('')
                        pr_match = df_pr[df_pr['PR Number'] == pr_number]
                        department_name = pr_match.iloc[0]['Requisition Department'].strip() if not pr_match.empty else ''
                        pr_order_type_raw = pr_match.iloc[0].get('Order Type', '') if not pr_match.empty else ''
                        pr_order_type = str(pr_order_type_raw).strip().lower() if pr_order_type_raw is not None else ''
                        
                        # Compute refund amount = Basic Amount + Freight Charges
                        fr_amt = pd.to_numeric(po_row.get('Freight Charges', 0), errors='coerce') or 0
                        amount_to_credit = float(basic_amount) + float(fr_amt)
                        
                        app.logger.info(f"[PO {po}] POST Rejection - Refund: dept='{department_name}', order_type='{pr_order_type}', project='{project_number}', credit={amount_to_credit}")
                        
                        # Load project-specific budgets and credit back
                        if department_name and project_number:
                            df_budgets = load_project_budgets_for_pr(project_number)
                            if not df_budgets.empty and 'Department' in df_budgets.columns:
                                df_budgets.set_index('Department', inplace=True)
                                if department_name in df_budgets.index:
                                    budget_column = 'Service_Budget' if pr_order_type == 'services' else 'Material_Budget'
                                    if budget_column in df_budgets.columns:
                                        current_budget = pd.to_numeric(df_budgets.at[department_name, budget_column], errors='coerce')
                                        if pd.isna(current_budget):
                                            current_budget = 0
                                        new_budget = float(current_budget) + amount_to_credit
                                        df_budgets.at[department_name, budget_column] = new_budget
                                        df_budgets.reset_index(inplace=True)
                                        project_budget_file = get_project_budget_file_path(project_number)
                                        if project_budget_file and os.path.exists(project_budget_file):
                                            df_budgets.to_excel(project_budget_file, index=False)
                                            app.logger.info(f"[PO {po}] POST Rejection - Credited {amount_to_credit} back to {budget_column} for '{department_name}' (new={new_budget})")
                                        else:
                                            app.logger.warning(f"[PO {po}] POST Rejection - Project budget file not found for {project_number}; refund not persisted")
                                    else:
                                        app.logger.error(f"[PO {po}] POST Rejection - Budget column '{budget_column}' missing in budgets file")
                                else:
                                    app.logger.error(f"[PO {po}] POST Rejection - Department '{department_name}' not found in budgets file for project {project_number}")
                            else:
                                app.logger.error(f"[PO {po}] POST Rejection - Budgets dataframe empty or missing 'Department' for project {project_number}")
                        else:
                            app.logger.error(f"[PO {po}] POST Rejection - Missing department or project number; cannot credit budget back")
                except Exception as budget_err:
                    app.logger.exception(f"[PO {po}] POST Rejection - Error crediting budget back: {budget_err}")
                
                # Mark as Rejected & notify requester
                set_po_status("Rejected")

                # Get PO details for the details section
                po_row = df_po[df_po['PO Number'] == po].iloc[0]
                
                subject = f"Your PO {po} was Rejected"
                
                content = f"""
                  <p>Your Purchase Order has been <strong>Rejected</strong>.</p>
                  <p><strong>PO Number:</strong> <span class="amount-highlight">{po}</span></p>
                  <p><strong>Rejected by:</strong> {role}</p>
                  <p><strong>Rejection Reason:</strong> {rejection_reason}</p>
                  <p><strong>Additional Details:</strong> {rejection_details}</p>
                """
                
                if suggested_actions:
                    content += f"<p><strong>Suggested Actions:</strong> {suggested_actions}</p>"
                
                content += "<p>Please review the feedback and take appropriate action to address the issues.</p>"
                
                # Create details table for rejection notification
                po_items = get_po_items_for_email(po)
                details_table = create_po_details_table(
                    po_number=po,
                    project_name=f"{po_row.get('Project Number', '')} - {po_row.get('Project Name', '')}".strip(' - '),
                    pr_number=po_row.get('PR Number', ''),
                    company=po_row.get('Company Name', ''),
                    total_amount=po_row.get('Total Amount', ''),
                    basic_amount=po_row.get('Basic Amount', ''),
                    pf_amount=po_row.get('PF Charges', ''),
                    gst_amount=po_row.get('GST Amount', ''),
                    freight_amount=po_row.get('Freight Charges', ''),
                    other_amount=po_row.get('Other Charges', ''),
                    items=po_items
                )
                
                html = create_modern_email_template(
                    title="Purchase Order Rejected",
                    recipient_name="Requester",
                    content=content,
                    details_table=details_table,
                    footer_text="This is an automated notification from the Purchase Order Management System."
                )
                app.logger.info(f"[PO APPROVAL DEBUG] Sending Stage 1 rejection email to {requester_email}")
                try:
                    send_email(first_info['email'], requester_email, subject, html)
                    app.logger.info(f"[PO {po}] rejection notification sent to {requester_email}")
                except Exception as e:
                    app.logger.exception(f"[PO {po}] failed to notify requester on rejection: {e}")

                # Add notification for PO rejection
                add_notification(
                    'fas fa-times-circle',
                    f'Purchase Order {po} has been rejected by {role}',
                    po
                )
                
                # Remove chain from session
                session.pop(chain_key, None)
                return jsonify({'success': True, 'message': f'PO {po} rejected successfully with feedback'})
            else:
                app.logger.info(f"[PO APPROVAL DEBUG] Stage 1 rejection without feedback for PO {po}")
                # For GET requests, just update status to rejected
                set_po_status("Rejected")

                # Get PO details for the details section
                po_row = df_po[df_po['PO Number'] == po].iloc[0]
                
                subject = f"Your PO {po} was Rejected"
                
                content = f"""
                  <p>Your Purchase Order has been <strong>Rejected</strong>.</p>
                  <p><strong>PO Number:</strong> <span class="amount-highlight">{po}</span></p>
                  <p><strong>Rejected by:</strong> {role}</p>
                  <p>Please review the rejection and take appropriate action if needed.</p>
                """
                
                # Create details table for rejection notification
                po_items = get_po_items_for_email(po)
                details_table = create_po_details_table(
                    po_number=po,
                    project_name=f"{po_row.get('Project Number', '')} - {po_row.get('Project Name', '')}".strip(' - '),
                    pr_number=po_row.get('PR Number', ''),
                    company=po_row.get('Company Name', ''),
                    total_amount=po_row.get('Total Amount', ''),
                    basic_amount=po_row.get('Basic Amount', ''),
                    pf_amount=po_row.get('PF Charges', ''),
                    gst_amount=po_row.get('GST Amount', ''),
                    freight_amount=po_row.get('Freight Charges', ''),
                    other_amount=po_row.get('Other Charges', ''),
                    items=po_items
                )
                
                html = create_modern_email_template(
                    title="Purchase Order Rejected",
                    recipient_name="Requester",
                    content=content,
                    details_table=details_table,
                    footer_text="This is an automated notification from the Purchase Order Management System."
                )
                app.logger.info(f"[PO APPROVAL DEBUG] Sending Stage 1 rejection email to {requester_email}")
                try:
                    send_email(first_info['email'], requester_email, subject, html)
                    app.logger.info(f"[PO {po}] rejection notification sent to {requester_email}")
                except Exception as e:
                    app.logger.exception(f"[PO {po}] failed to notify requester on rejection: {e}")

                # Add notification for PO rejection
                add_notification(
                    'fas fa-times-circle',
                    f'Purchase Order {po} has been rejected by {role}',
                    po
                )
                
                # Remove chain from session
                session.pop(chain_key, None)
                return f"PO {po} rejected. Requester notified.", 200
        
        elif action == 'approve':
            app.logger.info(f"[PO APPROVAL DEBUG] Stage 1 approval for PO {po}")
            # First approver approved - check if there's a second approver
            if second_info:
                app.logger.info(f"[PO APPROVAL DEBUG] Sending PO {po} to second approver: {second_info['role']}")
                # Send to second approver
                set_po_status("First Approval Complete - Pending Second Approval")
                
                # Create approval URLs for second approver
                approve_url_2 = url_for('approval_page', type='po', action='approve', id=po, role=second_info['role'], _external=True, _scheme=app.config.get('PREFERRED_URL_SCHEME', 'https'))
                reject_url_2 = url_for('approval_page', type='po', action='reject', id=po, role=second_info['role'], _external=True, _scheme=app.config.get('PREFERRED_URL_SCHEME', 'https'))
                
                # Get PO details for the email
                po_row = df_po[df_po['PO Number'] == po].iloc[0]
                
                content = f"<p>A Purchase Order has been approved by {first_info['role']} and now requires your final approval.</p><p><strong>⚠️ IMPORTANT:</strong> Click the button below to review and approve/reject this PO. Do not use email preview links.</p>"
                action_buttons = [{"text": "🔍 Review & Approve/Reject", "url": approve_url_2, "color": "primary"}]
                
                po_items = get_po_items_for_email(po)
                details_table = create_po_details_table(
                    po_number=po,
                    project_name=f"{po_row.get('Project Number', '')} - {po_row.get('Project Name', '')}".strip(' - '),
                    pr_number=po_row.get('PR Number', ''),
                    company=po_row.get('Company Name', ''),
                    total_amount=po_row.get('Total Amount', ''),
                    basic_amount=po_row.get('Basic Amount', ''),
                    pf_amount=po_row.get('PF Charges', ''),
                    gst_amount=po_row.get('GST Amount', ''),
                    freight_amount=po_row.get('Freight Charges', ''),
                    other_amount=po_row.get('Other Charges', ''),
                    items=po_items
                )
                
                html_2 = create_modern_email_template(
                    title="Final PO Approval Required",
                    recipient_name=second_info['role'],
                    content=content,
                    action_buttons=action_buttons,
                    details_table=details_table
                )
                
                app.logger.info(f"[PO APPROVAL DEBUG] Sending Stage 2 approval request email to {second_info['email']}")
                try:
                    send_email(first_info['email'], second_info['email'], f"Final Approval Needed: PO {po}", html_2)
                    app.logger.info(f"[PO {po}] sent to second approver: {second_info['role']} ({second_info['email']})")
                except Exception as e:
                    app.logger.exception(f"[PO {po}] failed to send to second approver: {e}")
                    flash("Failed to send PO to second approver. Please check server logs.")
                    return jsonify({'success': False, 'message': 'Failed to send to second approver'}), 500
                
                # Add notification for first approval
                add_notification(
                    'fas fa-check-circle',
                    f'PO {po} approved by {first_info["role"]}, sent to {second_info["role"]} for final approval',
                    po
                )
                
                return jsonify({'success': True, 'message': f'PO {po} approved by {first_info["role"]}. Sent to {second_info["role"]} for final approval.'})
            else:
                app.logger.info(f"[PO APPROVAL DEBUG] No second approver - PO {po} fully approved")
                # No second approver - PO is fully approved
                set_po_status("Approved")
                
                # Notify requester of full approval
                po_row = df_po[df_po['PO Number'] == po].iloc[0]
                
                subject = f"Your PO {po} has been Fully Approved"
                content = f"""
                  <p>Great news! Your Purchase Order has been <strong>Fully Approved</strong> by {first_info['role']} and is now ready for execution.</p>
                  <p><strong>PO Number:</strong> <span class="amount-highlight">{po}</span></p>
                  <p>You can now proceed with the purchase.</p>
                """
                
                po_items = get_po_items_for_email(po)
                details_table = create_po_details_table(
                    po_number=po,
                    project_name=f"{po_row.get('Project Number', '')} - {po_row.get('Project Name', '')}".strip(' - '),
                    pr_number=po_row.get('PR Number', ''),
                    company=po_row.get('Company Name', ''),
                    total_amount=po_row.get('Total Amount', ''),
                    basic_amount=po_row.get('Basic Amount', ''),
                    pf_amount=po_row.get('PF Charges', ''),
                    gst_amount=po_row.get('GST Amount', ''),
                    freight_amount=po_row.get('Freight Charges', ''),
                    other_amount=po_row.get('Other Charges', ''),
                    items=po_items
                )
                
                html = create_modern_email_template(
                    title="Purchase Order Fully Approved",
                    recipient_name="Requester",
                    content=content,
                    details_table=details_table
                )
                
                app.logger.info(f"[PO APPROVAL DEBUG] Sending full approval email to {requester_email}")
                try:
                    send_email(first_info['email'], requester_email, subject, html)
                    app.logger.info(f"[PO {po}] full approval notification sent to {requester_email}")
                except Exception as e:
                    app.logger.exception(f"[PO {po}] failed to notify requester on full approval: {e}")
                
                # Add notification for full approval
                add_notification(
                    'fas fa-check-circle',
                    f'Purchase Order {po} has been fully approved by {first_info["role"]}',
                    po
                )
                
                # Remove chain from session
                session.pop(chain_key, None)
                return jsonify({'success': True, 'message': f'PO {po} fully approved by {first_info["role"]}.'})

    # ─── Stage 2 approval/rejection ──────────────────────────────────────────
    elif is_second:
        app.logger.info(f"[PO APPROVAL DEBUG] Processing Stage 2 {action} for PO {po}")
        if action == 'reject':
            app.logger.info(f"[PO APPROVAL DEBUG] Stage 2 rejection for PO {po}")
            
            # Credit budget back before marking as rejected
            try:
                # Load PO details
                po_row = df_po[df_po['PO Number'] == po].iloc[0]
                pr_number = po_row.get('PR Number', '').strip()
                project_number = po_row.get('Project Number', '').strip()
                basic_amount = pd.to_numeric(po_row.get('Basic Amount', 0), errors='coerce') or 0
                
                if basic_amount > 0:  # Only credit if budget was deducted
                    # Determine department and order type from PR
                    df_pr = pd.read_excel(DATA_FILE, dtype=str).fillna('')
                    pr_match = df_pr[df_pr['PR Number'] == pr_number]
                    department_name = pr_match.iloc[0]['Requisition Department'].strip() if not pr_match.empty else ''
                    pr_order_type_raw = pr_match.iloc[0].get('Order Type', '') if not pr_match.empty else ''
                    pr_order_type = str(pr_order_type_raw).strip().lower() if pr_order_type_raw is not None else ''
                    
                    # Compute refund amount = Basic Amount + Freight Charges
                    fr_amt = pd.to_numeric(po_row.get('Freight Charges', 0), errors='coerce') or 0
                    amount_to_credit = float(basic_amount) + float(fr_amt)
                    
                    app.logger.info(f"[PO {po}] Stage 2 Rejection - Refund: dept='{department_name}', order_type='{pr_order_type}', project='{project_number}', credit={amount_to_credit}")
                    
                    # Load project-specific budgets and credit back
                    if department_name and project_number:
                        df_budgets = load_project_budgets_for_pr(project_number)
                        if not df_budgets.empty and 'Department' in df_budgets.columns:
                            df_budgets.set_index('Department', inplace=True)
                            if department_name in df_budgets.index:
                                budget_column = 'Service_Budget' if pr_order_type == 'services' else 'Material_Budget'
                                if budget_column in df_budgets.columns:
                                    current_budget = pd.to_numeric(df_budgets.at[department_name, budget_column], errors='coerce')
                                    if pd.isna(current_budget):
                                        current_budget = 0
                                    new_budget = float(current_budget) + amount_to_credit
                                    df_budgets.at[department_name, budget_column] = new_budget
                                    df_budgets.reset_index(inplace=True)
                                    project_budget_file = get_project_budget_file_path(project_number)
                                    if project_budget_file and os.path.exists(project_budget_file):
                                        df_budgets.to_excel(project_budget_file, index=False)
                                        app.logger.info(f"[PO {po}] Stage 2 Rejection - Credited {amount_to_credit} back to {budget_column} for '{department_name}' (new={new_budget})")
                                    else:
                                        app.logger.warning(f"[PO {po}] Stage 2 Rejection - Project budget file not found for {project_number}; refund not persisted")
                                else:
                                    app.logger.error(f"[PO {po}] Stage 2 Rejection - Budget column '{budget_column}' missing in budgets file")
                            else:
                                app.logger.error(f"[PO {po}] Stage 2 Rejection - Department '{department_name}' not found in budgets file for project {project_number}")
                        else:
                            app.logger.error(f"[PO {po}] Stage 2 Rejection - Budgets dataframe empty or missing 'Department' for project {project_number}")
                    else:
                        app.logger.error(f"[PO {po}] Stage 2 Rejection - Missing department or project number; cannot credit budget back")
            except Exception as budget_err:
                app.logger.exception(f"[PO {po}] Stage 2 Rejection - Error crediting budget back: {budget_err}")
            
            # Second approver rejected - notify requester
            set_po_status("Rejected")
            
            # Get PO details for the details section
            po_row = df_po[df_po['PO Number'] == po].iloc[0]
            
            subject = f"Your PO {po} was Rejected"
            content = f"""
          <p>Your Purchase Order has been <strong>Rejected</strong> at the final approval stage.</p>
              <p><strong>PO Number:</strong> <span class="amount-highlight">{po}</span></p>
          <p><strong>Rejected by:</strong> {role}</p>
              <p>Please review the rejection and take appropriate action if needed.</p>
            """
            
            po_items = get_po_items_for_email(po)
            details_table = create_po_details_table(
                po_number=po,
                project_name=f"{po_row.get('Project Number', '')} - {po_row.get('Project Name', '')}".strip(' - '),
                pr_number=po_row.get('PR Number', ''),
                company=po_row.get('Company Name', ''),
                total_amount=po_row.get('Total Amount', ''),
                basic_amount=po_row.get('Basic Amount', ''),
                pf_amount=po_row.get('PF Charges', ''),
                gst_amount=po_row.get('GST Amount', ''),
                freight_amount=po_row.get('Freight Charges', ''),
                other_amount=po_row.get('Other Charges', ''),
                items=po_items
            )
            
            html = create_modern_email_template(
                title="Purchase Order Rejected",
                recipient_name="Requester",
                content=content,
                details_table=details_table,
                footer_text="This is an automated notification from the Purchase Order Management System."
                )
            
            app.logger.info(f"[PO APPROVAL DEBUG] Sending Stage 2 rejection email to {requester_email}")
            try:
                send_email(second_info['email'], requester_email, subject, html)
                app.logger.info(f"[PO {po}] rejection notification sent to {requester_email}")
            except Exception as e:
                app.logger.exception(f"[PO {po}] failed to notify requester on rejection: {e}")

            # Add notification for PO rejection
            add_notification(
                'fas fa-times-circle',
                f'Purchase Order {po} has been rejected by {role}',
                po
            )
            
            # Remove chain from session
            session.pop(chain_key, None)
            return jsonify({'success': True, 'message': f'PO {po} rejected by {role}.'})

        elif action == 'approve':
            app.logger.info(f"[PO APPROVAL DEBUG] Stage 2 approval for PO {po}")
            # Second approver approved - PO is fully approved
            set_po_status("Approved")
            
            # Notify requester of full approval
            po_row = df_po[df_po['PO Number'] == po].iloc[0]
            
            subject = f"Your PO {po} has been Fully Approved"
            content = f"""
              <p>Great news! Your Purchase Order has been <strong>Fully Approved</strong> by both {first_info['role']} and {second_info['role']} and is now ready for execution.</p>
              <p><strong>PO Number:</strong> <span class="amount-highlight">{po}</span></p>
              <p>You can now proceed with the purchase.</p>
            """
            
            po_items = get_po_items_for_email(po)
            details_table = create_po_details_table(
                po_number=po,
                project_name=f"{po_row.get('Project Number', '')} - {po_row.get('Project Name', '')}".strip(' - '),
                pr_number=po_row.get('PR Number', ''),
                company=po_row.get('Company Name', ''),
                total_amount=po_row.get('Total Amount', ''),
                basic_amount=po_row.get('Basic Amount', ''),
                pf_amount=po_row.get('PF Charges', ''),
                gst_amount=po_row.get('GST Amount', ''),
                freight_amount=po_row.get('Freight Charges', ''),
                other_amount=po_row.get('Other Charges', ''),
                items=po_items
            )
            
            html = create_modern_email_template(
                title="Purchase Order Fully Approved",
                recipient_name="Requester",
                content=content,
                details_table=details_table
            )
            
            app.logger.info(f"[PO APPROVAL DEBUG] Sending final approval email to {requester_email}")
            try:
                send_email(second_info['email'], requester_email, subject, html)
                app.logger.info(f"[PO {po}] approval notification sent to {requester_email}")
            except Exception as e:
                app.logger.exception(f"[PO {po}] failed to notify requester on approval: {e}")

            # Add notification for PO approval
            add_notification(
                'fas fa-check-circle',
                f'Purchase Order {po} has been fully approved by both {first_info["role"]} and {second_info["role"]}',
                po
            )
            
            # Also notify first approver that their approval led to full approval
            try:
                notify_first_approver_subject = f"PO {po} has been fully approved"
                notify_first_approver_content = f"""
                  <p>The Purchase Order {po} that you approved has been <strong>Fully Approved</strong> by {second_info['role']}.</p>
                  <p>This PO is now ready for execution.</p>
                """
                
                html_first = create_modern_email_template(
                    title="PO Fully Approved",
                    recipient_name=first_info['role'],
                    content=notify_first_approver_content
                )
                
                app.logger.info(f"[PO APPROVAL DEBUG] Notifying first approver {first_info['email']} of final approval")
                send_email(second_info['email'], first_info['email'], notify_first_approver_subject, html_first)
                app.logger.info(f"[PO {po}] first approver notified of full approval")
            except Exception as e:
                app.logger.exception(f"[PO {po}] failed to notify first approver of full approval: {e}")
            
            # Cleanup chain
            session.pop(chain_key, None)
            return jsonify({'success': True, 'message': f'PO {po} fully approved by both {first_info["role"]} and {second_info["role"]}.'})

    else:
        app.logger.error(f"[PO APPROVAL DEBUG] Unexpected error: role '{role}' not in chain for PO {po}")
        return jsonify({'success': False, 'message': f"Unexpected error: role '{role}' not in chain for PO {po}."}), 500



@app.route('/filters', methods=['POST'])
@require_auth
def filters():
    # 1) Accept JSON or form-encoded
    if request.is_json:
        payload = request.get_json(silent=True) or {}
        vc = sanitize_input(payload.get('vendor_code', '').strip())
    else:
        vc = sanitize_input(request.form.get('vendor_code', '').strip())

    app.logger.info(f"[Filters] Looking up vendor_code={vc!r}")

    # 2) Safely load vendor_items.xlsx
    try:
        df = pd.read_excel(VENDOR_FILE,
                           dtype={'Vendor Code': str, 'Item Name': str, 'Additional Info': str},
                           engine='openpyxl')
    except Exception as e:
        app.logger.error(f"[Filters] Failed to read {VENDOR_FILE}: {e}")
        return jsonify({ "error": "Server error reading vendor data" }), 500

    # 3) Trim & filter - handle NaN values properly
    df = df.fillna('')
    df['Vendor Code'] = df['Vendor Code'].astype(str).str.strip()
    subset = df[df['Vendor Code'] == vc][['Item Name','Additional Info']]
    app.logger.info(f"[Filters] Found {len(subset)} rows for {vc!r}")

    # 4) Return JSON list - ensure proper data types
    result = []
    for _, row in subset.iterrows():
        result.append({
            'Item Name': str(row['Item Name']).strip(),
            'Additional Info': str(row['Additional Info']).strip()
        })
    
    return jsonify(result)


@app.route('/api/vendor_lookup', methods=['POST'])
@require_auth
def vendor_lookup():
    """Look up vendor details by vendor code for PO form auto-fill"""
    try:
        if request.is_json:
            payload = request.get_json(silent=True) or {}
            vendor_code = sanitize_input(payload.get('vendor_code', '').strip())
        else:
            vendor_code = sanitize_input(request.form.get('vendor_code', '').strip())

        if not vendor_code:
            return jsonify({'error': 'Vendor code is required'}), 400

        app.logger.info(f"[Vendor Lookup] Looking up vendor_code={vendor_code!r}")

        # Load vendor_items.xlsx
        try:
            df = pd.read_excel(VENDOR_FILE, dtype=str, engine='openpyxl')
        except Exception as e:
            app.logger.error(f"[Vendor Lookup] Failed to read {VENDOR_FILE}: {e}")
            return jsonify({'error': 'Server error reading vendor data'}), 500

        # Filter by vendor code and get unique vendor details
        df = df.fillna('')
        df['Vendor Code'] = df['Vendor Code'].str.strip()
        vendor_rows = df[df['Vendor Code'] == vendor_code]

        if vendor_rows.empty:
            return jsonify({'error': f'Vendor code {vendor_code} not found'}), 404

        # Get the first row for vendor details (assuming vendor details are the same for all items)
        vendor_info = vendor_rows.iloc[0]
        
        # Return vendor details
        result = {
            'vendor_code': vendor_code,
            'company_name': vendor_info.get('Company Name', '').strip(),
            'vendor_address': vendor_info.get('Vendor Address', '').strip(),
            'gst_number': vendor_info.get('GST Number', '').strip(),
            'contact_person': vendor_info.get('Contact Person', '').strip(),
            'contact_mobile': vendor_info.get('Contact Mobile', '').strip(),
            'contact_email': vendor_info.get('Contact Email', '').strip(),
            'items': []
        }

        # Add all items for this vendor (excluding nan/empty items)
        for _, row in vendor_rows.iterrows():
            item_name = row.get('Item Name', '').strip()
            
            # Skip items with nan, empty, or invalid item names
            if not item_name or item_name.lower() in ['nan', 'none', 'null', '']:
                continue
                
            # Remove the [1], [2], etc. prefix from item names for display
            if item_name.startswith('[') and '] ' in item_name:
                item_name = item_name.split('] ', 1)[1]
            
            result['items'].append({
                'item_name': item_name,
                'additional_info': row.get('Additional Info', '').strip()
            })

        app.logger.info(f"[Vendor Lookup] Found vendor: {result['company_name']} with {len(result['items'])} items")
        return jsonify(result)

    except Exception as e:
        app.logger.error(f"[Vendor Lookup] Error: {e}")
        return jsonify({'error': 'Server error during vendor lookup'}), 500


@app.route('/api/vendor_search', methods=['POST'])
@require_auth
def vendor_search():
    """Search vendors by vendor code or company name"""
    try:
        if request.is_json:
            payload = request.get_json(silent=True) or {}
            search_term = sanitize_input(payload.get('search_term', '').strip())
            search_type = sanitize_input(payload.get('search_type', 'code').strip())  # 'code' or 'name'
        else:
            search_term = sanitize_input(request.form.get('search_term', '').strip())
            search_type = sanitize_input(request.form.get('search_type', 'code').strip())

        if not search_term:
            return jsonify({'error': 'Search term is required'}), 400

        app.logger.info(f"[Vendor Search] Searching by {search_type}: {search_term!r}")

        # Load vendor_items.xlsx
        try:
            df = pd.read_excel(VENDOR_FILE, dtype=str, engine='openpyxl')
        except Exception as e:
            app.logger.error(f"[Vendor Search] Failed to read {VENDOR_FILE}: {e}")
            return jsonify({'error': 'Server error reading vendor data'}), 500

        # Filter by search type
        df = df.fillna('')
        if search_type == 'name':
            # Search by company name (case-insensitive partial match)
            df['Company Name'] = df['Company Name'].str.strip()
            vendor_rows = df[df['Company Name'].str.lower().str.contains(search_term.lower())]
        else:
            # Search by vendor code (exact match)
            df['Vendor Code'] = df['Vendor Code'].str.strip()
            vendor_rows = df[df['Vendor Code'] == search_term]

        if vendor_rows.empty:
            return jsonify({'error': f'No vendors found for {search_type}: {search_term}'}), 404

        # Return all items for the found vendors (excluding nan/empty items)
        items = []
        for _, row in vendor_rows.iterrows():
            item_name = row.get('Item Name', '').strip()
            
            # Skip items with nan, empty, or invalid item names
            if not item_name or item_name.lower() in ['nan', 'none', 'null', '']:
                continue
                
            # Remove the [1], [2], etc. prefix from item names for display
            if item_name.startswith('[') and '] ' in item_name:
                item_name = item_name.split('] ', 1)[1]
            
            items.append({
                'vendor_code': row.get('Vendor Code', '').strip(),
                'company_name': row.get('Company Name', '').strip(),
                'item_name': item_name,
                'additional_info': row.get('Additional Info', '').strip()
            })

        app.logger.info(f"[Vendor Search] Found {len(items)} items for vendors")
        return jsonify({'items': items})

    except Exception as e:
        app.logger.error(f"[Vendor Search] Error: {e}")
        return jsonify({'error': 'Server error during vendor search'}), 500


@app.route('/pr_requisition', methods=['POST'])
@require_auth
def pr_requisition():
    form = request.form

    # ─── 1) Read basic form inputs and validate file upload ──────────────────
    
    # NEW: Validate that the file was submitted
    material_file = request.files.get('material_requisition_file')
    if not material_file or not material_file.filename:
        flash("A Material Requisition File is required. Please upload the document.")
        return redirect(url_for('po_system'))

    dept_name       = sanitize_input(form.get('department', '').strip())
    dept_code       = sanitize_input(form.get('department_code', '').strip())
    requester_role  = sanitize_input(form.get('name', '').strip())
    requester_email = sanitize_input(form.get('requester_email', '').strip())
    project_number  = sanitize_input(form.get('project_number', '').strip())
    project_name    = sanitize_input(form.get('pr-project_name', '').strip())
    order_type      = sanitize_input(form.get('order_type', '').strip())
    item_type       = sanitize_input(form.get('item_type', '').strip())
    expected_delivery_date = sanitize_input(form.get('expected_delivery_date', '').strip())
    priority_of_po  = sanitize_input(form.get('priority_of_po', '').strip())
    
    # Validate required fields
    if not all([dept_name, dept_code, requester_role, requester_email, project_number, project_name, order_type, item_type, expected_delivery_date, priority_of_po]):
        flash("All required fields must be filled.")
        return redirect(url_for('po_system'))
    
    # Validate email format
    if not validate_email(requester_email):
        flash("Invalid email format.")
        return redirect(url_for('po_system'))

    # ─── 2) All PRs now go directly to Head of Project Planning and Control ─────────────────────
    next_approver_role = "Head of Project Planning and Control"
    
    matches = dept_email_df[
        dept_email_df['Department'].str.lower() == next_approver_role.lower()
    ]
    if matches.empty:
        flash(f"No approver email found for {next_approver_role}.")
        return redirect(url_for('po_system'))
    approver_email = matches['Email'].iloc[0].strip()

    # ─── 3) Generate PR number ──────────────────────────────────────────────────
    pr_number = get_next_PR_number(project_number, dept_code)

    # ─── 4) Save the uploaded Material Requisition File ───────────────────────
    fn = secure_filename(material_file.filename)
    mr_filename = f"{pr_number}_{fn}"
    material_file.save(os.path.join(UPLOAD_MRF, mr_filename))

    # ─── 5) Build record rows and save PR to DATA_FILE ──────────────────────────
    n_items = int(form.get('number_of_items', '0'))
    records = []
    for i in range(1, n_items + 1):
        records.append({
            'PR Number':              pr_number,
            'Project Number':         project_number,
            'Project Name':           project_name,
            'Requisition Department': dept_name,
            'Discipline':             sanitize_input(form.get('discipline', '')),
            'Order Type':             order_type,
            'Name':                   requester_role,
            'Requester Email':        requester_email,
            'Date':                   sanitize_input(form.get('date', '')),
            'Expected Delivery Date': expected_delivery_date,
            'Priority of PO':         priority_of_po,
            'Number of Items':        str(n_items),  # Save the total number of items
            'Item Type':              item_type,
            'Item Name':              sanitize_input(form.get(f'item_{i}_name','')),
            'Item Description':       sanitize_input(form.get(f'item_{i}_description', '')),
            'Unit of Items':          sanitize_input(form.get(f'item_{i}_unit_items', '')),
            'Measurement':            sanitize_input(form.get(f'item_{i}_measurement', '')),
            'Unit Rate':              '',
            'Indicative Price':       '',
            'Budget Total':           '',
            'Remaining Budget':       '',
            'Material Requisition File': mr_filename, # Save the new filename
            'PR Status':              'Pending'
        })

    dfp = pd.read_excel(DATA_FILE, dtype=str).fillna('')
    new_rows_df = pd.DataFrame(records)
    # If this PR already exists, replace its rows; otherwise append
    if not dfp.empty and 'PR Number' in dfp.columns and (dfp['PR Number'].str.strip() == pr_number).any():
        dfp = dfp[dfp['PR Number'].str.strip() != pr_number]
        dfp = pd.concat([dfp, new_rows_df], ignore_index=True)
    else:
        dfp = pd.concat([dfp, new_rows_df], ignore_index=True)
    dfp.to_excel(DATA_FILE, index=False)
    
    # Create external approval URLs (scheme will be derived by the client/proxy)
    approve_url = url_for('approval_page', type='pr', action='approve', id=pr_number, role=next_approver_role, _external=True, _scheme=app.config.get('PREFERRED_URL_SCHEME', 'https'))
    reject_url = url_for('approval_page', type='pr', action='reject', id=pr_number, role=next_approver_role, _external=True, _scheme=app.config.get('PREFERRED_URL_SCHEME', 'https'))

    content = f"""
      <p>A new Purchase Requisition has been submitted and requires your approval.</p>
      <p><strong>⚠️ IMPORTANT:</strong> Click the button below to review and approve/reject this PR. Do not use email preview links.</p>
      <p><strong>PR Number:</strong> <span class="amount-highlight">{pr_number}</span></p>
      <p><strong>Submitted by:</strong> {requester_role} ({requester_email})</p>
      <p>Please review the details below. Financials will be handled during the PO generation.</p>
    """
    
    items_rows_html = ""
    for rec in records:
        items_rows_html += f"""
        <tr>
          <td>{rec['Item Name']}</td>
          <td>{rec['Item Description']}</td>
          <td>{rec['Unit of Items']}</td>
          <td>{rec['Measurement']}</td>
        </tr>
        """
        
    details_table = f"""
      <table class="details-table">
        <tr><th>Field</th><th>Value</th></tr>
        <tr><td><strong>PR Number</strong></td><td>{pr_number}</td></tr>
        <tr><td><strong>Project</strong></td><td>{f"{project_number} - {project_name}".strip(' - ')}</td></tr>
        <tr><td><strong>Department</strong></td><td>{dept_name}</td></tr>
        <tr><td><strong>Requested by</strong></td><td>{requester_role} ({requester_email})</td></tr>
        <tr><td><strong>Expected Delivery Date</strong></td><td>{expected_delivery_date}</td></tr>
        <tr><td><strong>Priority</strong></td><td>{priority_of_po}</td></tr>
      </table>
      
      <h3 style="margin-top: 20px; color: #2c3e50; font-size: 16px; font-weight: 700;">Item Details</h3>
      <table class="details-table">
        <thead>
          <tr>
            <th>Item Name</th>
            <th>Description</th>
            <th>Quantity</th>
            <th>UOM</th>
          </tr>
        </thead>
        <tbody>
          {items_rows_html}
        </tbody>
      </table>
    """
    
    action_buttons = [
        {"text": "🔍 Review & Approve/Reject", "url": approve_url, "color": "primary"}
    ]
    
    html = create_modern_email_template(
        title="Purchase Requisition Approval Required",
        recipient_name=next_approver_role,
        content=content,
        action_buttons=action_buttons,
        details_table=details_table,
        footer_text="This is an automated notification from the Purchase Order Management System."
    )

    try:
        # Add Material Requisition file as attachment
        attachment_path = os.path.join(UPLOAD_MRF, mr_filename)
        attachment_name = f"Material_Requisition_{pr_number}.{mr_filename.split('.')[-1] if '.' in mr_filename else 'docx'}"
        
        # Send email with attachment
        send_email(requester_email, approver_email, f"Approval Needed: PR {pr_number}", html, attachment_path, attachment_name)
        app.logger.info(f"PR approval email sent with attachment: {attachment_path}")
        
    except Exception as e:
        app.logger.exception(f"[PR {pr_number}] failed to send approval email: {e}")
        flash("Failed to send approval email. Please check the server log.")
        return redirect(url_for('po_system'))

    add_notification('fas fa-clipboard-list', f'PR {pr_number} submitted, pending approval from {next_approver_role}', pr_number)
    
    flash(f"Your Purchase Request has been submitted. PR: {pr_number}")
    return redirect(url_for('po_system'))



# ─── PR Approval Processing Functions ────────────────────────────────────────
def process_pr_approval(pr_number, approver):
    """Process PR approval directly from email link"""
    try:
        # Load PR data
        df = pd.read_excel(DATA_FILE, dtype=str).fillna('')
        df['PR Number'] = df['PR Number'].str.strip()
        idx_list = df.index[df['PR Number'] == pr_number].tolist()
        
        if not idx_list:
            return render_template('approval_pages.html', 
                                type='pr', 
                                action='approve', 
                                id=pr_number, 
                                role=approver,
                                error=f"PR {pr_number} not found.")
        
        # Get the first row that matches the PR number
        row_index = idx_list[0]
        pr_row = df.iloc[row_index]
        req_email = pr_row['Requester Email'].strip()
        
        # Update all rows for this PR number to 'Approved'
        df.loc[df['PR Number'] == pr_number, 'PR Status'] = 'Approved'
        df.to_excel(DATA_FILE, index=False)
        
        # Find the approver's email to send the notification from
        approver_email_from_df = dept_email_df[dept_email_df['Department'].str.lower() == 'head of project planning and control']
        if approver_email_from_df.empty:
            approver_email_from = 'project.planning@adventz.com'
        else:
            approver_email_from = approver_email_from_df['Email'].iloc[0]
        
        # Get PR items for email
        pr_items = get_pr_items_for_email(pr_number)
        
        # Send approval notification
        subject = f"Your PR {pr_number} has been Approved"
        content = f"""
          <p>Great news! Your Purchase Requisition has been <strong>Approved</strong> by the Head of Project Planning and Control and is now ready for the next stage.</p>
          <p><strong>PR Number:</strong> <span class="amount-highlight">{pr_number}</span></p>
          <p>You can now proceed to generate a Purchase Order against this PR.</p>
        """
        details_table = create_pr_details_table(
            pr_number=pr_number, project_number=pr_row.get('Project Number', ''),
            department=pr_row.get('Requisition Department', ''), requester_role=pr_row.get('Name', ''),
            requester_email=req_email, total_budget='', budget_deducted='', remaining_budget='',
            project_name=pr_row.get('Project Name', ''), items=pr_items
        )
        html = create_modern_email_template(title="Purchase Requisition Approved", recipient_name="Requester", content=content, details_table=details_table)
        
        try:
            send_email(approver_email_from, req_email, subject, html)
            app.logger.info(f"[PR {pr_number}] approval notification sent to {req_email}")
        except Exception as e:
            app.logger.exception(f"[PR {pr_number}] failed to notify requester on approval: {e}")
        
        # Send notification to Head of Procurement with PR details and Material Requisition file
        try:
            # Get Head of Procurement email
            procurement_email_df = dept_email_df[dept_email_df['Department'].str.lower() == 'head of procurement']
            if not procurement_email_df.empty:
                procurement_email = procurement_email_df['Email'].iloc[0].strip()
                
                # Create notification email for Head of Procurement
                procurement_subject = f"PR {pr_number} - Approved and Ready for Processing"
                procurement_content = f"""
                  <p>This is to inform you that Purchase Requisition <strong>{pr_number}</strong> has been approved by Head of Project Planning and Control.</p>
                  <p>The PR is now ready for Purchase Order generation and processing.</p>
                  <p><strong>PR Number:</strong> <span class="amount-highlight">{pr_number}</span></p>
                  <p>Please find the complete PR details and Material Requisition file attached for your reference.</p>
                """
                procurement_html = create_modern_email_template(
                    title="Purchase Requisition Approved - For Your Information", 
                    recipient_name="Head of Procurement", 
                    content=procurement_content, 
                    details_table=details_table
                )
                
                # Find and attach the Material Requisition file
                attachment_path = None
                attachment_name = None
                try:
                    # Look for the MR file in the upload directory
                    mr_files = [f for f in os.listdir(UPLOAD_MRF) if f.startswith(f"{pr_number}_")]
                    if mr_files:
                        attachment_path = os.path.join(UPLOAD_MRF, mr_files[0])
                        attachment_name = f"Material_Requisition_{pr_number}.{mr_files[0].split('.')[-1] if '.' in mr_files[0] else 'docx'}"
                        app.logger.info(f"[PR {pr_number}] Found MR file for attachment: {attachment_path}")
                except Exception as e:
                    app.logger.warning(f"[PR {pr_number}] Could not find MR file for attachment: {e}")
                
                # Send email to Head of Procurement
                send_email(approver_email_from, procurement_email, procurement_subject, procurement_html, attachment_path, attachment_name)
                app.logger.info(f"[PR {pr_number}] notification sent to Head of Procurement: {procurement_email}")
            else:
                app.logger.warning(f"[PR {pr_number}] Head of Procurement email not found in department emails")
        except Exception as e:
            app.logger.exception(f"[PR {pr_number}] failed to notify Head of Procurement: {e}")
        
        add_notification('fas fa-check-circle', f'Purchase Request {pr_number} has been approved by Head of Project Planning and Control', pr_number)
        
        # Redirect to approval page with success message
        return redirect(url_for('approval_page', 
                              type='pr', 
                              action='approve', 
                              id=pr_number, 
                              role=approver,
                              message=f"PR {pr_number} has been successfully approved!"))
        
    except Exception as e:
        app.logger.exception(f"Error processing PR approval: {e}")
        return render_template('approval_pages.html', 
                            type='pr', 
                            action='approve', 
                            id=pr_number, 
                            role=approver,
                            error=f"Error processing approval: {str(e)}")

def process_pr_rejection(pr_number, approver):
    """Process PR rejection directly from email link"""
    try:
        # Load PR data
        df = pd.read_excel(DATA_FILE, dtype=str).fillna('')
        df['PR Number'] = df['PR Number'].str.strip()
        idx_list = df.index[df['PR Number'] == pr_number].tolist()
        
        if not idx_list:
            return render_template('approval_pages.html', 
                                type='pr', 
                                action='reject', 
                                id=pr_number, 
                                role=approver,
                                error=f"PR {pr_number} not found.")
        
        # Get the first row that matches the PR number
        row_index = idx_list[0]
        pr_row = df.iloc[row_index]
        req_email = pr_row['Requester Email'].strip()
        
        # Update all rows for this PR number to 'Rejected'
        df.loc[df['PR Number'] == pr_number, 'PR Status'] = 'Rejected'
        df.to_excel(DATA_FILE, index=False)
        
        # Find the approver's email to send the notification from
        approver_email_from_df = dept_email_df[dept_email_df['Department'].str.lower() == 'head of procurement']
        if approver_email_from_df.empty:
            approver_email_from = 'procurement.head@adventz.com'
        else:
            approver_email_from = approver_email_from_df['Email'].iloc[0]
        
        # Send rejection notification
        subject = f"Your PR {pr_number} was Rejected"
        content = f"""
          <p>Your Purchase Requisition has been <strong>Rejected</strong> by the Head of Procurement.</p>
          <p><strong>PR Number:</strong> <span class="amount-highlight">{pr_number}</span></p>
          <p>Please review the rejection and take appropriate action if needed.</p>
        """
        details_table = create_pr_details_table(
            pr_number=pr_number, project_number=pr_row.get('Project Number', ''),
            department=pr_row.get('Requisition Department', ''), requester_role=pr_row.get('Name', ''),
            requester_email=req_email, total_budget='', budget_deducted='', remaining_budget='',
            project_name=pr_row.get('Project Name', '')
        )
        html = create_modern_email_template(title="Purchase Requisition Rejected", recipient_name="Requester", content=content, details_table=details_table)
        
        try:
            send_email(approver_email_from, req_email, subject, html)
            app.logger.info(f"[PR {pr_number}] rejection notification sent to {req_email}")
        except Exception as e:
            app.logger.exception(f"[PR {pr_number}] failed to notify requester on rejection: {e}")
        
        add_notification('fas fa-times-circle', f'Purchase Request {pr_number} has been rejected by Head of Project Planning and Control', pr_number)
        
        # Redirect to approval page with success message
        return redirect(url_for('approval_page', 
                              type='pr', 
                              action='reject', 
                              id=pr_number, 
                              role=approver,
                              message=f"PR {pr_number} has been successfully rejected!"))
        
    except Exception as e:
        app.logger.exception(f"Error processing PR rejection: {e}")
        return render_template('approval_pages.html', 
                            type='pr', 
                            action='reject', 
                            id=pr_number, 
                            role=approver,
                            error=f"Error processing rejection: {str(e)}")

# ─── Approval Handler ─────────────────────────────────────────────────────────
@app.route('/approve_pr', methods=['GET', 'POST'])
def approve_pr():
    # Support both GET (query params) and POST (form fields)
    pr_number = sanitize_input((request.args.get('pr') or request.form.get('pr_number', '')).strip())
    action    = sanitize_input((request.args.get('action') or request.form.get('action', '')).lower())  # "approve" or "reject"
    approver  = sanitize_input((request.args.get('role') or request.form.get('role', '')).strip())      # e.g. "Head of Procurement"
    
    # Rate limiting check
    if not check_rate_limit(request.remote_addr, f"pr_{pr_number}_{action}", limit_seconds=5):
        app.logger.warning(f"[PR APPROVAL DEBUG] Rate limited: {request.remote_addr} for PR {pr_number} {action}")
        return jsonify({'success': False, 'message': 'Too many requests. Please wait a few seconds and try again.'}), 429

    if not pr_number or action not in ('approve', 'reject') or not approver:
        return "Invalid request", 400

    # If this is a GET request from email link, process the approval directly and RETURN EARLY
    if request.method == 'GET':
        # Process approval/rejection directly from email link
        if action == 'approve':
            return process_pr_approval(pr_number, approver)
        elif action == 'reject':
            return process_pr_rejection(pr_number, approver)
        else:
            return render_template('approval_pages.html', 
                                type='pr', 
                                action='approve', 
                                id=pr_number, 
                                role=approver,
                                error="Invalid action specified")

    # POST request logic continues here (for form submissions from approval page)
    # Load PR data
    df = pd.read_excel(DATA_FILE, dtype=str).fillna('')
    df['PR Number'] = df['PR Number'].str.strip()
    idx_list = df.index[df['PR Number'] == pr_number].tolist()
    if not idx_list:
        return f"PR {pr_number} not found.", 404
    
    # Get the first row that matches the PR number
    row_index = idx_list[0]
    pr_row = df.iloc[row_index]
    req_email = pr_row['Requester Email'].strip()

    # The entire approval logic is now streamlined for a single approver role
    if approver == "Head of Project Planning and Control":
        # Find the approver's email to send the notification from
        approver_email_from_df = dept_email_df[dept_email_df['Department'].str.lower() == 'head of project planning and control']
        if approver_email_from_df.empty:
             # Fallback or error if email not found
            approver_email_from = 'project.planning@adventz.com'
        else:
            approver_email_from = approver_email_from_df['Email'].iloc[0]

        if action == 'approve':
            # Update all rows for this PR number to 'Approved'
            df.loc[df['PR Number'] == pr_number, 'PR Status'] = 'Approved'
            df.to_excel(DATA_FILE, index=False)
            
            # Get PR items for email
            pr_items = get_pr_items_for_email(pr_number)
            
            subject = f"Your PR {pr_number} has been Approved"
            content = f"""
              <p>Great news! Your Purchase Requisition has been <strong>Approved</strong> by the Head of Project Planning and Control and is now ready for the next stage.</p>
              <p><strong>PR Number:</strong> <span class="amount-highlight">{pr_number}</span></p>
              <p>You can now proceed to generate a Purchase Order against this PR.</p>
            """
            details_table = create_pr_details_table(
                pr_number=pr_number, project_number=pr_row.get('Project Number', ''),
                department=pr_row.get('Requisition Department', ''), requester_role=pr_row.get('Name', ''),
                requester_email=req_email, total_budget='', budget_deducted='', remaining_budget='',
                project_name=pr_row.get('Project Name', ''), items=pr_items
            )
            html = create_modern_email_template(title="Purchase Requisition Approved", recipient_name="Requester", content=content, details_table=details_table)
            
            send_email(approver_email_from, req_email, subject, html)
            
            # Send notification to Head of Procurement with PR details and Material Requisition file
            try:
                # Get Head of Procurement email
                procurement_email_df = dept_email_df[dept_email_df['Department'].str.lower() == 'head of procurement']
                if not procurement_email_df.empty:
                    procurement_email = procurement_email_df['Email'].iloc[0].strip()
                    
                    # Create notification email for Head of Procurement
                    procurement_subject = f"PR {pr_number} - Approved and Ready for Processing"
                    procurement_content = f"""
                      <p>This is to inform you that Purchase Requisition <strong>{pr_number}</strong> has been approved by Head of Project Planning and Control.</p>
                      <p>The PR is now ready for Purchase Order generation and processing.</p>
                      <p><strong>PR Number:</strong> <span class="amount-highlight">{pr_number}</span></p>
                      <p>Please find the complete PR details and Material Requisition file attached for your reference.</p>
                    """
                    procurement_html = create_modern_email_template(
                        title="Purchase Requisition Approved - For Your Information", 
                        recipient_name="Head of Procurement", 
                        content=procurement_content, 
                        details_table=details_table
                    )
                    
                    # Find and attach the Material Requisition file
                    attachment_path = None
                    attachment_name = None
                    try:
                        # Look for the MR file in the upload directory
                        mr_files = [f for f in os.listdir(UPLOAD_MRF) if f.startswith(f"{pr_number}_")]
                        if mr_files:
                            attachment_path = os.path.join(UPLOAD_MRF, mr_files[0])
                            attachment_name = f"Material_Requisition_{pr_number}.{mr_files[0].split('.')[-1] if '.' in mr_files[0] else 'docx'}"
                            app.logger.info(f"[PR {pr_number}] Found MR file for attachment: {attachment_path}")
                    except Exception as e:
                        app.logger.warning(f"[PR {pr_number}] Could not find MR file for attachment: {e}")
                    
                    # Send email to Head of Procurement
                    send_email(approver_email_from, procurement_email, procurement_subject, procurement_html, attachment_path, attachment_name)
                    app.logger.info(f"[PR {pr_number}] notification sent to Head of Procurement: {procurement_email}")
                else:
                    app.logger.warning(f"[PR {pr_number}] Head of Procurement email not found in department emails")
            except Exception as e:
                app.logger.exception(f"[PR {pr_number}] failed to notify Head of Procurement: {e}")
            
            add_notification('fas fa-check-circle', f'Purchase Request {pr_number} has been approved by Head of Project Planning and Control', pr_number)
            
            # Return JSON response for AJAX requests
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': True, 'message': f'PR {pr_number} approved successfully'})
            else:
                return f"PR {pr_number} approved. Requester notified.", 200
        
        else: # action == 'reject'
            # Handle rejection with feedback if this is a POST request
            if request.method == 'POST':
                rejection_reason = sanitize_input(request.form.get('rejection_reason', ''))
                rejection_details = sanitize_input(request.form.get('rejection_details', ''))
                suggested_actions = sanitize_input(request.form.get('suggested_actions', ''))
                
                if not rejection_reason or not rejection_details:
                    return jsonify({'success': False, 'message': 'Rejection reason and details are required'}), 400
                
                # Update all rows for this PR number to 'Rejected'
                df.loc[df['PR Number'] == pr_number, 'PR Status'] = 'Rejected'
                df.to_excel(DATA_FILE, index=False)
                
                subject = f"Your PR {pr_number} was Rejected"
                content = f"""
                  <p>Your Purchase Requisition has been <strong>Rejected</strong> by the Head of Project Planning and Control.</p>
                  <p><strong>PR Number:</strong> <span class="amount-highlight">{pr_number}</span></p>
                  <p><strong>Rejection Reason:</strong> {rejection_reason}</p>
                  <p><strong>Additional Details:</strong> {rejection_details}</p>
                """
                
                if suggested_actions:
                    content += f"<p><strong>Suggested Actions:</strong> {suggested_actions}</p>"
                
                content += "<p>Please review the feedback and take appropriate action to address the issues.</p>"
                
                details_table = create_pr_details_table(
                    pr_number=pr_number, project_number=pr_row.get('Project Number', ''),
                    department=pr_row.get('Requisition Department', ''), requester_role=pr_row.get('Name', ''),
                    requester_email=req_email, total_budget='', budget_deducted='', remaining_budget='',
                    project_name=pr_row.get('Project Name', '')
                )
                html = create_modern_email_template(title="Purchase Requisition Rejected", recipient_name="Requester", content=content, details_table=details_table)
                
                send_email(approver_email_from, req_email, subject, html)
                add_notification('fas fa-times-circle', f'Purchase Request {pr_number} has been rejected by Head of Project Planning and Control', pr_number)
                
                return jsonify({'success': True, 'message': f'PR {pr_number} rejected successfully with feedback'})
            else:
                # For GET requests, just update status to rejected
                df.loc[df['PR Number'] == pr_number, 'PR Status'] = 'Rejected'
                df.to_excel(DATA_FILE, index=False)
                
                subject = f"Your PR {pr_number} was Rejected"
                content = f"""
                  <p>Your Purchase Requisition has been <strong>Rejected</strong> by the Head of Procurement.</p>
                  <p><strong>PR Number:</strong> <span class="amount-highlight">{pr_number}</span></p>
                  <p>Please review the rejection and take appropriate action if needed.</p>
                """
                details_table = create_pr_details_table(
                    pr_number=pr_number, project_number=pr_row.get('Project Number', ''),
                    department=pr_row.get('Requisition Department', ''), requester_role=pr_row.get('Name', ''),
                    requester_email=req_email, total_budget='', budget_deducted='', remaining_budget='',
                    project_name=pr_row.get('Project Name', '')
                )
                html = create_modern_email_template(title="Purchase Requisition Rejected", recipient_name="Requester", content=content, details_table=details_table)
                
                send_email(approver_email_from, req_email, subject, html)
                add_notification('fas fa-times-circle', f'Purchase Request {pr_number} has been rejected by Head of Project Planning and Control', pr_number)
                
                return f"PR {pr_number} rejected. Requester notified.", 200

    else:
        # This handles any clicks from old, outdated email links
        return f"Unknown or outdated approver role: {approver}. This PR now follows a simplified approval process.", 400




@app.route('/get_all_pos', methods=['GET'])
@require_auth
def get_all_pos():
    df = pd.read_excel(EXCEL_FILE)
    # Return only the fields the UI needs
    records = df[['Date', 'PO Number', 'Company Name','Total Amount']].to_dict(orient='records')
    return jsonify(records)

@app.route('/get_all_prs', methods=['GET'])
@require_auth
def get_all_prs():
    """Get all PRs for View PR section - only rejected PRs"""
    try:
        df = pd.read_excel(DATA_FILE, dtype=str).fillna('')
        
        # Filter only rejected PRs and remove empty entries
        df_filtered = df[
            (df['PR Status'].str.strip().str.lower() == 'rejected') & 
            (df['PR Number'].str.strip() != '') &
            (df['PR Number'].notna())
        ]
        
        # DON'T remove duplicates - we need all rows for multi-item PRs
        # Each row represents one item, so we need all rows for proper editing
        
        # Return all PR fields for editing (including all item rows)
        records = df_filtered.to_dict(orient='records')
        
        app.logger.info(f"get_all_prs - Returning {len(records)} records for rejected PRs")
        return jsonify(records)
    except Exception as e:
        app.logger.error(f"Error fetching PRs: {e}")
        return jsonify({'error': 'Failed to fetch PRs'}), 500

@app.route('/update_pr', methods=['POST'])
@require_auth
def update_pr():
    """Update PR details in data.xlsx and send email to approver"""
    try:
        # Handle both JSON and form data
        if request.is_json:
            form_data = request.get_json()
            pr_number = sanitize_input(form_data.get('pr_number', '').strip())
        else:
            form_data = request.form.to_dict()
            pr_number = sanitize_input(form_data.get('pr_number', '').strip())
        
        # Debug logging
        app.logger.info(f"PR Update - Form data received: {form_data}")
        app.logger.info(f"PR Update - PR Number: {pr_number}")
        app.logger.info(f"PR Update - Form data keys: {list(form_data.keys())}")
        
        # Debug item fields specifically
        item_fields = {k: v for k, v in form_data.items() if k.startswith('item_')}
        app.logger.info(f"PR Update - Item fields found: {item_fields}")
        
        if not pr_number:
            return jsonify({'success': False, 'message': 'PR Number is required'}), 400
        
        # Load current PR data
        df = pd.read_excel(DATA_FILE, dtype=str).fillna('')
        
        # Find the PR to update
        pr_index = df[df['PR Number'] == pr_number].index
        if pr_index.empty:
            return jsonify({'success': False, 'message': 'PR not found'}), 404
        
        # Store original data for comparison
        original_data = df.iloc[pr_index[0]].to_dict()
        
        # Handle file upload if present
        if 'material_requisition_file' in request.files:
            file = request.files['material_requisition_file']
            if file and file.filename:
                # Save the file
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                form_data['material_requisition_file'] = filename
                app.logger.info(f"File uploaded: {filename}")
        
        # Handle number of items change
        new_num_items = int(form_data.get('number_of_items', 1))
        # Get original number of items from the first row of this PR
        original_pr_rows = df[df['PR Number'] == pr_number]
        if not original_pr_rows.empty:
            original_num_items = int(original_pr_rows.iloc[0].get('Number of Items', 1))
        else:
            original_num_items = 1
        
        # Update the PR data - map form fields to Excel columns
        updated_fields = []
        
        # Define field mappings (form field name -> Excel column name)
        field_mappings = {
            'department': 'Requisition Department',
            'discipline': 'Discipline',
            'order_type': 'Order Type',
            'name': 'Name',
            'requester_email': 'Requester Email',
            'date': 'Date',
            'number_of_items': 'Number of Items'
        }
        
        # Update base fields using mappings
        for form_field, excel_column in field_mappings.items():
            if form_field in form_data and excel_column in df.columns:
                old_value = str(original_data.get(excel_column, '')).strip()
                new_value = sanitize_input(str(form_data.get(form_field, '')).strip())
                if old_value != new_value:
                    updated_fields.append(f"{excel_column}: '{old_value}' → '{new_value}'")
                    # Update all rows for this PR
                    df.loc[df['PR Number'] == pr_number, excel_column] = new_value
                    app.logger.info(f"PR Update - Updated {excel_column}: '{old_value}' → '{new_value}'")
        
        # Update item-specific fields for existing items (when number of items doesn't change)
        app.logger.info(f"PR Update - Checking item update condition: new_num_items={new_num_items}, original_num_items={original_num_items}")
        if new_num_items == original_num_items:
            app.logger.info(f"PR Update - Number of items unchanged ({new_num_items}), updating existing item fields")
            for i in range(1, new_num_items + 1):
                item_name = form_data.get(f'item_{i}_name', '')
                item_desc = form_data.get(f'item_{i}_description', '')
                item_qty = form_data.get(f'item_{i}_unit_items', '1')
                item_measurement = form_data.get(f'item_{i}_measurement', '')
                
                app.logger.info(f"PR Update - Updating existing item {i}: name='{item_name}', desc='{item_desc}', qty='{item_qty}', measurement='{item_measurement}'")
                
                # Update the specific row for this item
                pr_rows = df[df['PR Number'] == pr_number]
                app.logger.info(f"PR Update - Found {len(pr_rows)} rows for PR {pr_number}")
                
                # Debug: Show the structure of rows
                for idx, (row_idx, row_data) in enumerate(pr_rows.iterrows()):
                    app.logger.info(f"PR Update - Row {idx}: index={row_idx}, Item Name='{row_data.get('Item Name', '')}', Item Description='{row_data.get('Item Description', '')}'")
                
                # For multiple items, the first row (index 0) is the base PR row
                # Subsequent rows (index 1, 2, 3...) are the actual item rows
                if i == 1 and len(pr_rows) >= 1:
                    # First item: update the base PR row (first row)
                    row_index = pr_rows.index[0]
                    df.at[row_index, 'Item Name'] = item_name
                    df.at[row_index, 'Item Description'] = item_desc
                    df.at[row_index, 'Unit of Items'] = item_qty
                    df.at[row_index, 'Measurement'] = item_measurement
                    app.logger.info(f"PR Update - Updated base PR row {row_index} for item {i}")
                elif i > 1 and len(pr_rows) >= i:
                    # Subsequent items: update the corresponding item row (i-1 index)
                    row_index = pr_rows.index[i-1]
                    df.at[row_index, 'Item Name'] = item_name
                    df.at[row_index, 'Item Description'] = item_desc
                    df.at[row_index, 'Unit of Items'] = item_qty
                    df.at[row_index, 'Measurement'] = item_measurement
                    app.logger.info(f"PR Update - Updated item row {row_index} for item {i}")
                else:
                    app.logger.warning(f"PR Update - Not enough rows for item {i}, only {len(pr_rows)} rows available")
        else:
            app.logger.info(f"PR Update - Number of items changed from {original_num_items} to {new_num_items}, will regenerate rows")
        
        # Update project fields
        if 'project_number' in form_data and 'Project Number' in df.columns:
            old_value = str(original_data.get('Project Number', '')).strip()
            new_value = sanitize_input(str(form_data.get('project_number', '')).strip())
            if old_value != new_value:
                updated_fields.append(f"Project Number: '{old_value}' → '{new_value}'")
                df.loc[df['PR Number'] == pr_number, 'Project Number'] = new_value
        
        if 'project_name' in form_data and 'Project Name' in df.columns:
            old_value = str(original_data.get('Project Name', '')).strip()
            new_value = sanitize_input(str(form_data.get('project_name', '')).strip())
            if old_value != new_value:
                updated_fields.append(f"Project Name: '{old_value}' → '{new_value}'")
                df.loc[df['PR Number'] == pr_number, 'Project Name'] = new_value
        
        # Handle item rows based on number of items
        if new_num_items != original_num_items:
            # Remove existing item rows for this PR
            df = df[df['PR Number'] != pr_number]
            
            # Get the base PR data (first row)
            base_pr_data = original_data.copy()
            
            # Update base fields using the same mappings
            for form_field, excel_column in field_mappings.items():
                if form_field in form_data and excel_column in base_pr_data:
                    base_pr_data[excel_column] = sanitize_input(str(form_data.get(form_field, '')).strip())
            
            # Update project fields
            if 'project_number' in form_data:
                base_pr_data['Project Number'] = sanitize_input(str(form_data.get('project_number', '')).strip())
            if 'project_name' in form_data:
                base_pr_data['Project Name'] = sanitize_input(str(form_data.get('project_name', '')).strip())
            
            # Create new item rows
            new_rows = []
            for i in range(1, new_num_items + 1):
                item_data = base_pr_data.copy()
                # Update item-specific fields from form data - use correct field names
                item_name = form_data.get(f'item_{i}_name', '')
                item_desc = form_data.get(f'item_{i}_description', '')
                item_qty = form_data.get(f'item_{i}_unit_items', '1')
                item_measurement = form_data.get(f'item_{i}_measurement', '')
                
                app.logger.info(f"PR Update - Item {i}: name='{item_name}', desc='{item_desc}', qty='{item_qty}', measurement='{item_measurement}'")
                
                item_data['Item Name'] = item_name
                item_data['Item Description'] = item_desc
                item_data['Unit of Items'] = item_qty
                item_data['Measurement'] = item_measurement
                new_rows.append(item_data)
            
            # Add new rows to dataframe
            new_rows_df = pd.DataFrame(new_rows)
            df = pd.concat([df, new_rows_df], ignore_index=True)
            
            updated_fields.append(f"Number of Items: {original_num_items} → {new_num_items}")
            updated_fields.append("Item rows regenerated based on new count")
        
        # Reset PR status to pending for re-approval on ALL rows for this PR
        df.loc[df['PR Number'] == pr_number, 'PR Status'] = 'Pending'
        
        # Save back to Excel
        df.to_excel(DATA_FILE, index=False)
        
        # Debug logging
        app.logger.info(f"PR Update - Updated fields detected: {updated_fields}")
        app.logger.info(f"PR Update - Total updated fields count: {len(updated_fields)}")
        app.logger.info(f"PR Update - Form data keys: {list(form_data.keys())}")
        app.logger.info(f"PR Update - Excel columns: {list(df.columns)}")
        
        # Always send email when PR is updated (even if no fields changed, status changed)
        try:
            # Get PR details for email
            pr_rows = df[df['PR Number'] == pr_number]
            if not pr_rows.empty:
                pr_data = pr_rows.iloc[0]
                project_number = pr_data.get('Project Number', '').strip()
                department = pr_data.get('Requisition Department', '').strip()
                
                # Get approver email based on department
                approver_email = get_department_approver_email(department)
                
                if approver_email:
                    # Create email content
                    subject = f"PR {pr_number} - Updated and Requires Re-approval"
                    
                    # Get current PR data for complete details
                    current_pr_data = df[df['PR Number'] == pr_number].iloc[0]
                    
                    # Create comprehensive email body
                    body = f"""
                    <html>
                    <head>
                        <style>
                            body {{ font-family: Arial, sans-serif; margin: 20px; }}
                            .header {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
                            .section {{ margin-bottom: 20px; }}
                            .field {{ margin-bottom: 10px; }}
                            .label {{ font-weight: bold; color: #495057; }}
                            .value {{ color: #212529; }}
                            .updated {{ background-color: #fff3cd; padding: 5px; border-left: 4px solid #ffc107; }}
                            .items-table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
                            .items-table th, .items-table td {{ border: 1px solid #dee2e6; padding: 8px; text-align: left; }}
                            .items-table th {{ background-color: #f8f9fa; font-weight: bold; }}
                            .status {{ background-color: #d4edda; color: #155724; padding: 10px; border-radius: 5px; text-align: center; }}
                        </style>
                    </head>
                    <body>
                        <div class="header">
                            <h2 style="margin: 0; color: #495057;">Purchase Request Updated</h2>
                            <p style="margin: 5px 0; color: #6c757d;">PR Number: {pr_number}</p>
                        </div>
                        
                        <div class="section">
                            <h3>Project Information</h3>
                            <div class="field">
                                <span class="label">Project Number:</span>
                                <span class="value">{current_pr_data.get('Project Number', 'N/A')}</span>
                            </div>
                            <div class="field">
                                <span class="label">Project Name:</span>
                                <span class="value">{current_pr_data.get('Project Name', 'N/A')}</span>
                            </div>
                        </div>
                        
                        <div class="section">
                            <h3>Requester Details</h3>
                            <div class="field">
                                <span class="label">Name:</span>
                                <span class="value">{current_pr_data.get('Name', 'N/A')}</span>
                            </div>
                            <div class="field">
                                <span class="label">Email:</span>
                                <span class="value">{current_pr_data.get('Requester Email', 'N/A')}</span>
                            </div>
                            <div class="field">
                                <span class="label">Department:</span>
                                <span class="value">{current_pr_data.get('Requisition Department', 'N/A')}</span>
                            </div>
                            <div class="field">
                                <span class="label">Discipline:</span>
                                <span class="value">{current_pr_data.get('Discipline', 'N/A')}</span>
                            </div>
                            <div class="field">
                                <span class="label">Order Type:</span>
                                <span class="value">{current_pr_data.get('Order Type', 'N/A')}</span>
                            </div>
                            <div class="field">
                                <span class="label">Date:</span>
                                <span class="value">{current_pr_data.get('Date', 'N/A')}</span>
                            </div>
                        </div>
                        
                        <div class="section">
                            <h3>Item Details</h3>
                            <table class="items-table">
                                <thead>
                                    <tr>
                                        <th>Item</th>
                                        <th>Name</th>
                                        <th>Description</th>
                                        <th>Quantity</th>
                                        <th>Measurement</th>
                                    </tr>
                                </thead>
                                <tbody>
                    """
                    
                    # Add item rows
                    pr_rows = df[df['PR Number'] == pr_number]
                    for idx, (row_idx, row_data) in enumerate(pr_rows.iterrows()):
                        body += f"""
                                    <tr>
                                        <td>{idx + 1}</td>
                                        <td>{row_data.get('Item Name', 'N/A')}</td>
                                        <td>{row_data.get('Item Description', 'N/A')}</td>
                                        <td>{row_data.get('Unit of Items', 'N/A')}</td>
                                        <td>{row_data.get('Measurement', 'N/A')}</td>
                                    </tr>
                        """
                    
                    body += f"""
                                </tbody>
                            </table>
                        </div>
                    """
                    
                    # Add updated fields section if any
                    if updated_fields:
                        body += f"""
                        <div class="section">
                            <h3>Updated Fields (Requires Re-approval)</h3>
                            <div class="updated">
                                <ul style="margin: 10px 0; padding-left: 20px;">
                        """
                        for field in updated_fields:
                            body += f'<li>{field}</li>'
                        
                        body += """
                                </ul>
                            </div>
                        </div>
                        """
                    
                    body += f"""
                        <div class="status">
                            <strong>⚠️ This PR has been updated and requires re-approval before a Purchase Order can be generated.</strong>
                        </div>
                        
                        <div style="margin-top: 20px; padding: 15px; background-color: #f8f9fa; border-radius: 5px;">
                            <p style="margin: 0; color: #6c757d;">
                                Please review the changes above and approve/reject accordingly.<br>
                                <strong>Best regards,<br>ERP System</strong>
                            </p>
                        </div>
                    </body>
                    </html>
                    """
                    
                    # Check if there's a Material Requisition file to attach
                    attachment_path = None
                    attachment_name = None
                    
                    if current_pr_data.get('Material Requisition File'):
                        file_name = current_pr_data.get('Material Requisition File')
                        if file_name and file_name.strip():
                            # Construct the full file path
                            attachment_path = os.path.join(app.config['UPLOAD_FOLDER'], file_name)
                            attachment_name = f"Material_Requisition_{pr_number}.{file_name.split('.')[-1] if '.' in file_name else 'docx'}"
                            app.logger.info(f"Will attach file: {attachment_path}")
                    
                    # Send email with attachment if available
                    send_email(pr_data.get('Requester Email', ''), approver_email, subject, body, attachment_path, attachment_name)
                    app.logger.info(f"Email sent to {approver_email} for updated PR {pr_number}")
                else:
                    app.logger.warning(f"No approver email found for department: {department}")
                    
        except Exception as email_error:
            app.logger.error(f"Error sending email for PR {pr_number}: {email_error}")
        
        app.logger.info(f"PR {pr_number} updated successfully")
        return jsonify({'success': True, 'message': f'PR {pr_number} updated successfully and sent for re-approval'})
        
    except Exception as e:
        app.logger.error(f"Error updating PR: {e}")
        return jsonify({'success': False, 'message': 'Failed to update PR'}), 500

@app.route("/api/pr_items")
@require_auth
def api_pr_items():
    project = sanitize_input(request.args.get("project_number", "").strip())
    pr_num  = sanitize_input(request.args.get("pr_number", "").strip())

    df_pr = pd.read_excel(DATA_FILE, dtype=str).fillna("")
    df_sel  = df_pr[df_pr["Project Number"] == project]
    if pr_num:
       df_sel = df_sel[df_sel["PR Number"] == pr_num]

    items = []
    department = '' # Default value
    order_type = '' # Default value
    item_type = '' # Default value
    if not df_sel.empty:
        first_row = df_sel.iloc[0]
        department = first_row.get('Requisition Department', '') # Get department from the first item
        order_type = first_row.get('Order Type', '')
        item_type = first_row.get('Item Type', '')
        for _, row in df_sel.iterrows():
            items.append({
                "name":            row["Item Name"],
                "additional_info": row["Item Description"],
                "quantity":        row["Unit of Items"],
                "uom":             row["Measurement"],
                "unit_rate":       row["Unit Rate"]
            })

    po_number = get_next_PO_number(project)

    return jsonify({ 
       "items":     items, 
       "po_number": po_number,
       "department": department, # Add department to the response
       "order_type": order_type,
       "item_type": item_type
    })

def load_po_df():
    try:
        df = pd.read_excel(EXCEL_FILE, dtype=str).fillna('')
        if df.empty or 'Date' not in df.columns:
            return pd.DataFrame(columns=['Date', 'YearMonth', 'Total Amount', 'Company Name', 'Budget Spend'])

        df['Date'] = pd.to_datetime(df['Date'], errors='coerce')
        df.dropna(subset=['Date'], inplace=True)
        df['YearMonth'] = df['Date'].dt.to_period('M').astype(str)
        
        # Convert amount columns to numeric, supporting alternate column names
        basic_col_candidates = [
            'Total Basic Amount', 'Basic Amount', 'BasicAmount', 'Basic_Amount'
        ]
        freight_col_candidates = [
            'Total Freight', 'Freight Charges', 'Freight', 'Freight_Charges'
        ]

        def pick_numeric(series_candidates):
            for name in series_candidates:
                if name in df.columns:
                    return pd.to_numeric(df[name], errors='coerce').fillna(0)
            # if none found, return zeros
            return pd.Series([0] * len(df), index=df.index, dtype=float)

        basic_numeric = pick_numeric(basic_col_candidates)
        freight_numeric = pick_numeric(freight_col_candidates)

        # Preserve normalized numeric columns for downstream use
        df['__basic_numeric'] = basic_numeric
        df['__freight_numeric'] = freight_numeric

        # Keep Total Amount if present for compatibility (not used for spend calc)
        if 'Total Amount' in df.columns:
            df['Total Amount'] = pd.to_numeric(df['Total Amount'], errors='coerce').fillna(0)

        # Create the new 'Budget Spend' column for reporting
        df['Budget Spend'] = df['__basic_numeric'] + df['__freight_numeric']
        
        # CRITICAL FIX: Deduplicate by PO Number to avoid double-counting
        # When multiple items exist for same PO, only keep the first row (which contains PO-level data)
        if 'PO Number' in df.columns:
            df = df.drop_duplicates(subset=['PO Number'], keep='first')
            app.logger.info(f"After deduplication: {len(df)} unique POs (was {len(df) + len(df.drop_duplicates(subset=['PO Number'], keep=False))} total rows)")
        
        return df
    except FileNotFoundError:
        return pd.DataFrame(columns=['Date', 'YearMonth', 'Total Amount', 'Company Name', 'Budget Spend'])

@app.route('/api/monthly_po_count')
@require_auth
def monthly_po_count():
    df = load_po_df()

    if df.empty or 'Date' not in df.columns:
        return jsonify(labels=[], data=[])

    valid = df['Date'].dropna()
    if valid.empty:
        return jsonify(labels=[], data=[])

    grp = df.groupby('YearMonth').size().reset_index(name='count')

    first = valid.min().to_period('M')
    last  = valid.max().to_period('M')
    all_months = pd.period_range(first, last, freq='M').astype(str)
    full = pd.DataFrame({'YearMonth': all_months})

    merged = full.merge(grp, on='YearMonth', how='left').fillna(0)
    return jsonify(
        labels= merged['YearMonth'].tolist(),
        data=   merged['count'].astype(int).tolist()
    )

@app.route('/api/monthly_spend_trend')
@require_auth
def monthly_spend_trend():
    df = load_po_df()
    if df.empty: return jsonify(labels=[], data=[])
    
    # Filter out rejected POs before calculating spend
    df_approved = df[df['PO Status'].str.lower().str.strip().fillna('') != 'rejected']
    
    grp = df_approved.groupby('YearMonth')['Budget Spend'].sum().reset_index() # Use 'Budget Spend'
    
    valid = df['Date'].dropna()
    if valid.empty: return jsonify(labels=[], data=[])
    first = valid.min().to_period('M')
    last  = valid.max().to_period('M')
    all_months = pd.period_range(first, last, freq='M').astype(str)
    full = pd.DataFrame({'YearMonth': all_months})
    merged = full.merge(grp, on='YearMonth', how='left').fillna(0)

    return jsonify(
        labels= merged['YearMonth'].tolist(),
        data=   merged['Budget Spend'].tolist()
    )


@app.route('/api/top_vendors_by_spend')
@require_auth
def top_vendors_by_spend():
    df = load_po_df()
    if df.empty: return jsonify(labels=[], data=[])
    
    # Filter out rejected POs before calculating spend
    df_approved = df[df['PO Status'].str.lower().str.strip().fillna('') != 'rejected']
    
    grp = (df_approved.groupby('Company Name')['Budget Spend'] # Use 'Budget Spend'
             .sum()
             .sort_values(ascending=False)
             .head(5)
             .reset_index())
    return jsonify(labels=grp['Company Name'].tolist(),
                   data= grp['Budget Spend'].tolist())

@app.route('/api/avg_po_value_by_month')
@require_auth
def avg_po_value_by_month():
    df = load_po_df()
    if df.empty: return jsonify(labels=[], data=[])
    
    # Filter out rejected POs before calculating average
    df_approved = df[df['PO Status'].str.lower().str.strip().fillna('') != 'rejected']
    
    grp = df_approved.groupby('YearMonth')['Budget Spend'].mean().reset_index() # Use 'Budget Spend'
    return jsonify(labels=grp['YearMonth'].tolist(),
                   data= grp['Budget Spend'].round(2).tolist())

@app.route('/status_pr')
@require_auth
def status_pr():
    pr = sanitize_input(request.args.get('pr', '').strip())
    df = pd.read_excel(DATA_FILE, dtype=str).fillna('')
    df['PR Number'] = df['PR Number'].str.strip()
    row = df[df['PR Number'] == pr]
    if row.empty:
        return jsonify({ 'message': f"PR {pr} not found." }), 404

    st = row['PR Status'].iloc[0].strip().lower()
    if st == 'approved':
        msg = f"Purchase Request {pr} has been Approved."
    elif st == 'rejected':
        msg = f"Your Purchase Request {pr} is Rejected, Kindly Check with Approver."
    else:
        msg = f"Your Purchase Request {pr} is awaiting Confirmation, Please Contact Approver."

    return jsonify({ 'message': msg })


@app.route('/status_po')
@require_auth
def status_po():
    po = sanitize_input(request.args.get('po', '').strip())
    df = pd.read_excel(EXCEL_FILE, dtype=str).fillna('')
    df['PO Number'] = df['PO Number'].str.strip()
    row = df[df['PO Number'] == po]
    if row.empty:
        return jsonify({ 'message': f"PO {po} not found." }), 404

    st = row['PO Status'].iloc[0].strip().lower() if 'PO Status' in row else ''
    if st == 'approved':
        msg = f"Your Purchase Order {po} has been Approved."
        download_url = url_for('download_saved_po', po=po)
        
        # Check if additional documents exist
        additional_docs_folder = os.path.join(BASE_DIR, "additional_documents", po)
        has_additional_docs = False
        if os.path.exists(additional_docs_folder):
            additional_files = [f for f in os.listdir(additional_docs_folder) 
                              if os.path.isfile(os.path.join(additional_docs_folder, f))]
            has_additional_docs = len(additional_files) > 0
        
        additional_docs_url = url_for('download_additional_docs', po=po) if has_additional_docs else None
    elif st == 'rejected':
        msg = f"Your Purchase Order {po} is Rejected, Kindly Check with Approver."
        download_url = None
        additional_docs_url = None
    else:
        msg = f"Your Purchase Order {po} is awaiting Confirmation, Please Contact Approver."
        download_url = None
        additional_docs_url = None

    return jsonify({ 
        'message': msg, 
        'download_url': download_url,
        'additional_docs_url': additional_docs_url
    })


@app.route('/api/get_rejected_pos', methods=['GET'])
@require_auth
def get_rejected_pos():
    """Get all rejected POs for editing"""
    try:
        df_po = pd.read_excel(EXCEL_FILE, dtype=str).fillna('')
        df_po['PO Number'] = df_po['PO Number'].str.strip()
        
        # Filter for rejected POs
        rejected_pos = df_po[df_po['PO Status'].str.lower() == 'rejected']
        
        if rejected_pos.empty:
            return jsonify({
                'success': True,
                'purchase_orders': []
            })
        
        # Get unique POs (in case there are multiple rows per PO)
        unique_pos = rejected_pos.drop_duplicates(subset=['PO Number'])
        
        purchase_orders = []
        for _, row in unique_pos.iterrows():
            purchase_orders.append({
                'po_number': row['PO Number'],
                'project_name': row.get('Project Name', ''),
                'po_date': row.get('PO Date', ''),
                'pr_number': row.get('PR Number', ''),
                'requester_email': row.get('PO Requester Email', '')
            })
        
        return jsonify({
            'success': True,
            'purchase_orders': purchase_orders
        })
        
    except Exception as e:
        app.logger.exception(f"Error getting rejected POs: {e}")
        return jsonify({
            'success': False,
            'message': 'Error retrieving rejected POs'
        }), 500

    # Note: get_po_for_editing() removed - use get_po_full() instead for comprehensive data

# Note: get_po_items() removed - items are now fetched in get_po_full() from data.xlsx

@app.route('/api/get_po_full/<po_number>', methods=['GET'])
@require_auth
def get_po_full(po_number: str):
    """Return comprehensive PO details including PR and vendor context for editing."""
    try:
        po_number = sanitize_input(po_number.strip())
        df_po = pd.read_excel(EXCEL_FILE, dtype=str).fillna('')
        df_po['PO Number'] = df_po['PO Number'].str.strip()
        po_rows = df_po[df_po['PO Number'] == po_number]
        if po_rows.empty:
            return jsonify({'success': False, 'message': 'PO not found'}), 404

        # Use first row for header-level fields
        po_row = po_rows.iloc[0]

        # Fetch items from PO_data.xlsx (same file, different rows for same PO)
        items = []
        app.logger.info(f"[Edit PO] Fetching items from PO_data.xlsx for PO: {po_number}")
        
        # Get all rows for this PO (each item is a separate row)
        for idx, row in po_rows.iterrows():
            item_data = {
                'item_name': row.get('Item Name', ''),
                'additional_info': row.get('Additional Info', ''),
                'quantity': row.get('Quantity', ''),
                'uom': row.get('UOM', ''),
                'unit_rate': row.get('Unit Rate', '')
            }
            app.logger.info(f"[Edit PO] Item {idx}: {item_data}")
            items.append(item_data)
        
        # Fetch PR data from data.xlsx using PR number
        pr_data = {}
        pr_number = po_row.get('PR Number', '').strip()
        if pr_number and os.path.exists(DATA_FILE):
            try:
                df_pr = pd.read_excel(DATA_FILE, dtype=str).fillna('')
                df_pr['PR Number'] = df_pr['PR Number'].str.strip()
                pr_rows_data = df_pr[df_pr['PR Number'] == pr_number]
                
                if not pr_rows_data.empty:
                    pr_first = pr_rows_data.iloc[0]
                    pr_data = {
                        'project_number': pr_first.get('Project Number', ''),
                        'project_name': pr_first.get('Project Name', ''),
                        'department': pr_first.get('Requisition Department', ''),
                        'discipline': pr_first.get('Discipline', ''),
                        'order_type': pr_first.get('Order Type', ''),
                        'item_type': pr_first.get('Item Type', ''),
                        'date': pr_first.get('Date', ''),
                        'expected_delivery_date': pr_first.get('Expected Delivery Date', ''),
                        'priority_of_po': pr_first.get('Priority of PO', '')
                    }
            except Exception as e:
                app.logger.error(f"[Edit PO] Error fetching PR data from data.xlsx: {e}")

        # Fetch vendor details from vendor_items.xlsx using Vendor Code
        vendor_context = {}
        try:
            if os.path.exists(VENDOR_FILE):
                df_vendor = pd.read_excel(VENDOR_FILE, dtype=str).fillna('')
                vendor_code = po_row.get('Vendor Code', '').strip()
                app.logger.info(f"[Edit PO] Looking up vendor for code: '{vendor_code}'")
                
                if vendor_code:
                    vrows = df_vendor[df_vendor['Vendor Code'].str.strip() == vendor_code]
                    if not vrows.empty:
                        v = vrows.iloc[0]
                        app.logger.info(f"[Edit PO] Found vendor data: {dict(v)}")
                        
                        # Get vendor info from vendor_items.xlsx
                        vendor_context = {
                            'vendor_code': v.get('Vendor Code', ''),
                            'company_name': v.get('Company Name', ''),
                            'company_address': v.get('Vendor Address', ''),
                            'gst_number': v.get('GST Number', ''),
                            'contact_person_name': v.get('Contact Person', ''),
                            'contact_person_email': v.get('Contact Email', ''),
                            'contact_person_mobile': v.get('Contact Mobile', '')
                        }
                        app.logger.info(f"[Edit PO] Vendor context created: {vendor_context}")
                    else:
                        app.logger.warning(f"[Edit PO] No vendor found for code: '{vendor_code}'")
                else:
                    app.logger.warning(f"[Edit PO] No vendor code found in PO data")
        except Exception as e:
            app.logger.warning(f"Could not fetch vendor details for vendor code '{vendor_code}': {e}")

        # Compose PO header - all data from PO_data.xlsx, vendor details from vendor_items.xlsx
        po_header = {
            'po_number': po_row.get('PO Number', ''),
            'pr_number': pr_number,
            'project_number': po_row.get('Project Number', ''),
            'project_name': po_row.get('Project Name', ''),
            'company': po_row.get('Company Name', ''),
            'po_requester_role': po_row.get('PO Requester Role', ''),
            'po_requester_email': po_row.get('PO Requester Email', ''),
            'po_date': po_row.get('PO Date', ''),
            'delivery_date': po_row.get('Delivery Date', ''),
            'number_of_items': po_row.get('Number of Items', str(len(items) or '1')),
            'basic_amount': po_row.get('Basic Amount', ''),
            'pf_charges': po_row.get('PF Charges', ''),
            'freight_charges': po_row.get('Freight Charges', ''),
            'other_charges': po_row.get('Other Charges', ''),
            'gst_amt': po_row.get('GST Amount', ''),
            'total_amount': po_row.get('Total Amount', ''),
            # All form fields from PO_data.xlsx
            'vendor_code': po_row.get('Vendor Code', ''),
            'your_reference': po_row.get('Your Reference', ''),
            'price_basis': po_row.get('Price Basis', ''),
            'payment_term': po_row.get('Payment Terms', ''),
            'ship_to_location': po_row.get('Ship To Location', ''),
            'ship_to_address': po_row.get('Ship To Address', ''),
            'ship_to_gstin': po_row.get('Ship To GSTIN', ''),
            'bill_to_company': po_row.get('Bill To Company', ''),
            'bill_to_address': po_row.get('Bill To Address', ''),
            'bill_to_gstin': po_row.get('Bill To GSTIN', ''),
            'pf_rate': po_row.get('PF Rate', ''),
            'gst_rate': po_row.get('GST Rate', ''),
            'freight_rate': po_row.get('Freight Rate', ''),
            'other_rate': po_row.get('Other Rate', ''),
            # Vendor details from vendor_items.xlsx
            'company_address': vendor_context.get('company_address', ''),
            'gst': vendor_context.get('gst_number', ''),
            'contact_person_name': vendor_context.get('contact_person_name', ''),
            'contact_person_mobile': vendor_context.get('contact_person_mobile', ''),
            'contact_person_email': vendor_context.get('contact_person_email', '')
        }

        # Get budget information for the project
        budget_info = {}
        try:
            project_number = po_row.get('Project Number', '').strip()
            if project_number and pr_data.get('department') and pr_data.get('order_type'):
                df_budgets = load_project_budgets_for_pr(project_number)
                if not df_budgets.empty:
                    df_budgets.set_index('Department', inplace=True)
                    department = pr_data['department']
                    order_type = pr_data['order_type']
                    budget_column = 'Service_Budget' if order_type.lower() == 'services' else 'Material_Budget'
                    
                    if department in df_budgets.index and budget_column in df_budgets.columns:
                        total_budget = float(df_budgets.at[department, budget_column])
                        current_basic = float(po_row.get('Basic Amount', 0) or 0)
                        remaining_budget = total_budget - current_basic
                        
                        budget_info = {
                            'total_budget': int(total_budget) if total_budget.is_integer() else total_budget,
                            'remaining_budget': int(remaining_budget) if remaining_budget.is_integer() else remaining_budget,
                            'current_basic': int(current_basic) if current_basic.is_integer() else current_basic,
                            'department': department,
                            'order_type': order_type,
                            'budget_column': budget_column
                        }
        except Exception as e:
            app.logger.warning(f"Could not load budget info for PO {po_number}: {e}")

        app.logger.info(f"[Edit PO] Returning data - Items count: {len(items)}, PR data: {pr_data}, Budget: {budget_info}")
        
        # Convert any numpy types to Python native types for JSON serialization
        def convert_numpy_types(obj):
            if hasattr(obj, 'item'):  # numpy scalar
                return obj.item()
            elif hasattr(obj, 'tolist'):  # numpy array
                return obj.tolist()
            elif isinstance(obj, dict):
                return {k: convert_numpy_types(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_numpy_types(item) for item in obj]
            else:
                return obj
        
        response_data = {
            'success': True,
            'po': convert_numpy_types(po_header),
            'pr': convert_numpy_types(pr_data),
            'vendor': convert_numpy_types(vendor_context),
            'items': convert_numpy_types(items),
            'budget': convert_numpy_types(budget_info)
        }
        
        return jsonify(response_data)
    except Exception as e:
        app.logger.exception(f"Error building full PO details: {e}")
        return jsonify({'success': False, 'message': 'Server error building PO details'}), 500

@app.route('/api/get_priority_data', methods=['POST'])
@require_auth
def get_priority_data():
    """Get priority data for purchase requisitions"""
    try:
        data = request.get_json()
        priority_filter = data.get('priority_filter', 'critical')
        
        # Load PR data
        df = pd.read_excel(DATA_FILE, dtype=str).fillna('')
        df['PR Number'] = df['PR Number'].str.strip()
        
        # Filter for approved PRs only
        approved_prs = df[df['PR Status'].str.lower() == 'approved']
        
        if approved_prs.empty:
            return jsonify({
                'success': True,
                'purchase_requisitions': []
            })
        
        # Get unique PRs
        unique_prs = approved_prs.drop_duplicates(subset=['PR Number'])
        
        purchase_requisitions = []
        current_date = datetime.now()
        
        for _, row in unique_prs.iterrows():
            priority = row.get('Priority of PO', 'Non-Critical')
            expected_delivery_str = row.get('Expected Delivery Date', '')
            
            # Apply filters
            if priority_filter != 'all':
                if priority_filter == 'critical' and priority != 'Critical':
                    continue
                elif priority_filter == 'non-critical' and priority != 'Non-Critical':
                    continue
            
            # No secondary delivery filter
            
            purchase_requisitions.append({
                'pr_number': row['PR Number'],
                'project_name': row.get('Project Name', ''),
                'department': row.get('Requisition Department', ''),
                'requester_name': row.get('Name', ''),
                'priority': priority,
                'expected_delivery_date': expected_delivery_str,
                'date': row.get('Date', '')
            })
        
        return jsonify({
            'success': True,
            'purchase_requisitions': purchase_requisitions
        })
        
    except Exception as e:
        app.logger.exception(f"Error getting priority data: {e}")
        return jsonify({
            'success': False,
            'message': 'Error retrieving priority data'
        }), 500

@app.route('/update_po', methods=['POST'])
@require_auth
def update_po():
    """Update a rejected PO"""
    try:
        form_data = request.form.to_dict()
        po_number = sanitize_input(form_data.get('po_number', '').strip())
        
        if not po_number:
            flash("PO Number is required")
            return redirect(url_for('po_system'))
        
        # Load current PO data
        df_po = pd.read_excel(EXCEL_FILE, dtype=str).fillna('')
        df_po['PO Number'] = df_po['PO Number'].str.strip()
        
        # Check if PO exists and is rejected
        po_rows = df_po[df_po['PO Number'] == po_number]
        if po_rows.empty:
            flash("PO not found")
            return redirect(url_for('po_system'))
        
        if po_rows.iloc[0]['PO Status'].lower() != 'rejected':
            flash("Only rejected POs can be edited")
            return redirect(url_for('po_system'))
        
        # Update PO data
        num_items = int(form_data.get('number_of_items', 1))

        # Calculate old vs new basic (for budget diff)
        try:
            old_basic = pd.to_numeric(po_rows.iloc[0].get('Basic Amount', 0), errors='coerce') or 0
        except Exception:
            old_basic = 0

        # Recompute new amounts from submitted items
        new_basic = 0.0
        for i in range(1, num_items + 1):
            qty = float((form_data.get(f'item_{i}_quantity', '0') or '0').replace(',', ''))
            rate = float((form_data.get(f'item_{i}_unit_rate', '0') or '0').replace(',', ''))
            new_basic += qty * rate

        pf_rate = float((form_data.get('pf_rate', '0') or '0').strip('%'))
        gst_rate = float((form_data.get('gst_rate', '0') or '0').strip('%'))
        freight_rate = float((form_data.get('freight_rate', '0') or '0').strip('%'))
        other_rate = float((form_data.get('other_rate', '0') or '0').strip('%'))

        pf_amt = new_basic * (pf_rate / 100.0)
        gst_amt = new_basic * (gst_rate / 100.0)
        fr_amt  = new_basic * (freight_rate / 100.0)
        oth_amt = new_basic * (other_rate / 100.0)
        total_po = new_basic + pf_amt + gst_amt + fr_amt + oth_amt
        
        # Update basic fields for all rows of this PO
        df_po.loc[df_po['PO Number'] == po_number, 'PO Requester Role'] = sanitize_input(form_data.get('po_requester_role', ''))
        df_po.loc[df_po['PO Number'] == po_number, 'PO Requester Email'] = sanitize_input(form_data.get('po_requester_email', ''))
        df_po.loc[df_po['PO Number'] == po_number, 'PO Date'] = sanitize_input(form_data.get('po_date', ''))
        df_po.loc[df_po['PO Number'] == po_number, 'Delivery Date'] = sanitize_input(form_data.get('delivery_date', ''))
        df_po.loc[df_po['PO Number'] == po_number, 'Number of Items'] = str(num_items)
        
        # Update items in PO_data.xlsx
        for i in range(1, num_items + 1):
            item_name = sanitize_input(form_data.get(f'item_{i}_name', ''))
            additional_info = sanitize_input(form_data.get(f'item_{i}_additional_info', ''))
            quantity = sanitize_input(form_data.get(f'item_{i}_quantity', ''))
            uom = sanitize_input(form_data.get(f'item_{i}_uom', ''))
            unit_rate = sanitize_input(form_data.get(f'item_{i}_unit_rate', ''))
            
            # Update the i-th row for this PO
            po_indices = df_po[df_po['PO Number'] == po_number].index
            if i <= len(po_indices):
                idx = po_indices[i-1]
                df_po.loc[idx, 'Item Name'] = item_name
                df_po.loc[idx, 'Additional Info'] = additional_info
                df_po.loc[idx, 'Quantity'] = quantity
                df_po.loc[idx, 'UOM'] = uom
                df_po.loc[idx, 'Unit Rate'] = unit_rate
        
        # Reset PO status to Pending for re-approval
        df_po.loc[df_po['PO Number'] == po_number, 'PO Status'] = 'Pending'

        # Update header monetary fields
        df_po.loc[df_po['PO Number'] == po_number, 'Basic Amount'] = f"{new_basic:.2f}"
        df_po.loc[df_po['PO Number'] == po_number, 'PF Charges'] = f"{pf_amt:.2f}"
        df_po.loc[df_po['PO Number'] == po_number, 'Freight Charges'] = f"{fr_amt:.2f}"
        df_po.loc[df_po['PO Number'] == po_number, 'Other Charges'] = f"{oth_amt:.2f}"
        df_po.loc[df_po['PO Number'] == po_number, 'GST Amount'] = f"{gst_amt:.2f}"
        df_po.loc[df_po['PO Number'] == po_number, 'Total Amount'] = f"{total_po:.2f}"
        
        # Save the updated data
        # Budget diff adjust (based on PR department and order type)
        pr_number = po_rows.iloc[0].get('PR Number', '').strip()
        department_name = ''
        order_type = ''
        project_number = ''
        item_type = ''
        if os.path.exists(DATA_FILE) and pr_number:
            df_pr = pd.read_excel(DATA_FILE, dtype=str).fillna('')
            df_pr['PR Number'] = df_pr['PR Number'].str.strip()
            pr_rows = df_pr[df_pr['PR Number'] == pr_number]
            if not pr_rows.empty:
                r = pr_rows.iloc[0]
                department_name = r.get('Requisition Department', '').strip()
                order_type = (r.get('Order Type', '') or '').strip()
                project_number = r.get('Project Number', '').strip()
                item_type = (r.get('Item Type', '') or '').strip()

        # Decide budget column
        budget_column = 'Service_Budget' if (order_type.lower() == 'services') else 'Material_Budget'
        if project_number and department_name:
            df_budgets = load_project_budgets_for_pr(project_number)
            if not df_budgets.empty and 'Department' in df_budgets.columns and budget_column in df_budgets.columns:
                df_budgets.set_index('Department', inplace=True)
                if department_name in df_budgets.index:
                    current_val = float(df_budgets.at[department_name, budget_column])
                    # Old amount was previously deducted; compute difference
                    diff = new_basic - old_basic
                    # Deduct positive diff, credit negative diff
                    df_budgets.at[department_name, budget_column] = current_val - diff
                    df_budgets.reset_index(inplace=True)
                    project_budget_file = get_project_budget_file_path(project_number)
                    if project_budget_file:
                        try:
                            df_budgets.to_excel(project_budget_file, index=False)
                        except Exception:
                            app.logger.exception("Failed to persist budget diff during PO update")

        # Handle NFA replacement if provided
        try:
            if 'nfa_file' in request.files:
                nfa_file = request.files['nfa_file']
                if nfa_file and nfa_file.filename:
                    nfa_filename = secure_filename(nfa_file.filename)
                    nfa_filename = f"{pr_number}_{nfa_filename}"
                    nfa_path = os.path.join(UPLOAD_MRF, nfa_filename)
                    nfa_file.save(nfa_path)
                    app.logger.info(f"[PO Update] NFA file saved: {nfa_filename}")
        except Exception as e:
            app.logger.exception(f"[PO Update] Failed to handle NFA upload: {e}")

        # Replace Additional Documents for this PO if new ones are provided
        try:
            additional_docs_folder = os.path.join(BASE_DIR, "additional_documents", po_number)
            new_docs_uploaded = False
            incoming_files = {
                'tech_spec_file': request.files.get('tech_spec_file'),
                'price_comp_file': request.files.get('price_comp_file'),
                'nfa_doc_file': request.files.get('nfa_doc_file')
            }
            if any(f and f.filename for f in incoming_files.values()):
                # Clear existing files
                if os.path.exists(additional_docs_folder):
                    for fname in os.listdir(additional_docs_folder):
                        fpath = os.path.join(additional_docs_folder, fname)
                        try:
                            if os.path.isfile(fpath):
                                os.remove(fpath)
                        except Exception:
                            pass
                os.makedirs(additional_docs_folder, exist_ok=True)

                # Save new docs
                file_map = {
                    'tech_spec_file': 'Technical_Specification-Approved_MR_Copy',
                    'price_comp_file': 'Approved_Price_Comparative_Sheet',
                    'nfa_doc_file': 'Approved_NFA'
                }
                for key, prefix in file_map.items():
                    f = incoming_files.get(key)
                    if f and f.filename:
                        filename = secure_filename(f.filename)
                        name_part, ext = os.path.splitext(filename)
                        new_filename = f"{po_number}-{prefix}{ext}"
                        f.save(os.path.join(additional_docs_folder, new_filename))
                        new_docs_uploaded = True

                if new_docs_uploaded:
                    app.logger.info(f"[PO Update] Replaced additional documents for PO {po_number}")
        except Exception as e:
            app.logger.exception(f"[PO Update] Failed to handle additional documents: {e}")

        # Persist PO changes
        df_po.to_excel(EXCEL_FILE, index=False)
        
        # Send notification to approvers (similar to new PO creation)
        # This triggers the approval workflow again
        try:
            # Get PR details to determine approvers
            if pr_number and os.path.exists(DATA_FILE):
                df_pr = pd.read_excel(DATA_FILE, dtype=str).fillna('')
                df_pr['PR Number'] = df_pr['PR Number'].str.strip()
                pr_rows = df_pr[df_pr['PR Number'] == pr_number]
                
                if not pr_rows.empty:
                    pr_row = pr_rows.iloc[0]
                    department = pr_row.get('Requisition Department', '').strip()
                    
                    # Get approvers using the same logic as new PO creation
                    # This ensures consistency with the original approval workflow
                    
                    # Get required data for approval determination
                    discipline = pr_row.get('Discipline', '').strip()
                    po_requester_role = po_rows.iloc[0].get('PO Requester Role', '').strip()
                    
                    app.logger.info(f"[PO Update] Determining approvers for PO {po_number}:")
                    app.logger.info(f"[PO Update] - Discipline: '{discipline}'")
                    app.logger.info(f"[PO Update] - Requester Role: '{po_requester_role}'")
                    app.logger.info(f"[PO Update] - Basic Amount: {new_basic}")
                    
                    # Apply the same approval rules as new PO creation
                    t = new_basic  # Use basic amount for validation
                    first_approver = None
                    second_approver = None
                    
                    # Case A: discipline == Engineering
                    if discipline.lower() == 'engineering':
                        if t < 1_000_000:
                            first_approver, second_approver = "Head of Procurement", "CFO"
                        elif 1_000_000 <= t < 100_000_0000:
                            first_approver, second_approver = "CEO", None
                        else:
                            first_approver, second_approver = "Chairman", None
                    # Case B: discipline == Procurement
                    elif discipline.lower() == 'procurement':
                        if t < 2_500_000:
                            first_approver, second_approver = "Head of Procurement", "CFO"
                        else:
                            first_approver, second_approver = "CEO", None
                    # Case C: discipline == Construction
                    elif discipline.lower() == 'construction':
                        if t < 100_000:
                            first_approver, second_approver = "Head of Procurement", None
                        elif 100_000 <= t < 1_000_000:
                            first_approver, second_approver = "Head of Procurement", "CFO"
                        elif 1_000_000 <= t < 25_000_000:
                            first_approver, second_approver = "CEO", None
                        else:
                            first_approver, second_approver = "Chairman", None
                    else:
                        app.logger.warning(f"[PO Update] Unknown discipline: {discipline}, defaulting to Head of Procurement")
                        first_approver, second_approver = "Head of Procurement", None
                    
                    app.logger.info(f"[PO Update] Determined approvers: {first_approver}, {second_approver}")
                    
                    # Load department emails and get approver emails
                    dept_email_df = pd.read_excel(DEPT_EMAIL_FILE, dtype=str).fillna('')
                    
                    # Get first approver email
                    first_approver_email = None
                    if first_approver:
                        match_first = dept_email_df[dept_email_df['Department'].str.strip().str.lower() == first_approver.lower()]
                        if match_first.empty:
                            app.logger.warning(f"[PO Update] No email found for {first_approver}")
                        else:
                            first_approver_email = match_first.iloc[0]['Email'].strip()
                    
                    # Get second approver email
                    second_approver_email = None
                    if second_approver:
                        match_second = dept_email_df[dept_email_df['Department'].str.strip().str.lower() == second_approver.lower()]
                        if match_second.empty:
                            app.logger.warning(f"[PO Update] No email found for {second_approver}")
                        else:
                            second_approver_email = match_second.iloc[0]['Email'].strip()
                    
                    if first_approver and first_approver_email:
                        # Create approval URLs for first approver
                        approve_url_1 = url_for('approval_page', type='po', action='approve', id=po_number, role=first_approver, _external=True)
                        
                        # Create email content for updated PO
                        po_items = get_po_items_for_email(po_number)
                        details_table = create_po_details_table(
                            po_number=po_number, project_name=project_number, pr_number=pr_number,
                            company=po_rows.iloc[0].get('Company Name', ''), total_amount=f"{total_po:,.2f}",
                            basic_amount=f"{new_basic:,.2f}", pf_amount=f"{pf_amt:,.2f}", gst_amount=f"{gst_amt:,.2f}",
                            freight_amount=f"{fr_amt:,.2f}", other_amount=f"{oth_amt:,.2f}", items=po_items
                        )
                        
                        content = f"<p>A Purchase Order has been <strong>updated</strong> and requires your re-approval.</p><p><strong>⚠️ IMPORTANT:</strong> Click the button below to review and approve/reject this updated PO. Do not use email preview links.</p>"
                        action_buttons = [{"text": "🔍 Review & Approve/Reject", "url": approve_url_1, "color": "primary"}]
                        
                        html_1 = create_modern_email_template(
                            title="Purchase Order Update - Re-approval Required", 
                            recipient_name=first_approver, 
                            content=content,
                            action_buttons=action_buttons, 
                            details_table=details_table
                        )
                        
                        # Send email to first approver
                        requester_email = po_rows.iloc[0].get('PO Requester Email', '')
                        send_email(requester_email, first_approver_email, f"Re-approval Needed: Updated PO {po_number}", html_1)
                        app.logger.info(f"[PO Update] Re-approval email sent to {first_approver} ({first_approver_email})")
                        
                        # Store approval chain in database for persistence
                        approval_chain = {
                            "first": {"role": first_approver, "email": first_approver_email},
                            "second": None if not second_approver else {"role": second_approver, "email": second_approver_email},
                            "requester_email": requester_email
                        }
                        
                        # Store in session for immediate use
                        session[f"po_chain_{po_number}"] = approval_chain
                        
                        # Store in database for persistence
                        try:
                            conn = db.get_connection()
                            cursor = conn.cursor()
                            
                            # Create approval_chains table if it doesn't exist
                            cursor.execute('''
                                CREATE TABLE IF NOT EXISTS approval_chains (
                                    po_number TEXT PRIMARY KEY,
                                    chain_data TEXT NOT NULL,
                                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                                )
                            ''')
                            
                            # Store the chain data as JSON
                            import json
                            chain_json = json.dumps(approval_chain)
                            cursor.execute('''
                                INSERT OR REPLACE INTO approval_chains (po_number, chain_data)
                                VALUES (?, ?)
                            ''', (po_number, chain_json))
                            
                            conn.commit()
                            conn.close()
                            app.logger.info(f"Updated approval chain stored in database for PO {po_number}")
                            
                        except Exception as e:
                            app.logger.error(f"Failed to store updated approval chain in database: {e}")
                            
                        # Add notification
                        add_notification(
                            'fas fa-edit',
                            f'PO {po_number} updated and sent for re-approval to {first_approver}',
                            po_number
                        )
                        
                    else:
                        app.logger.warning(f"[PO Update] Could not determine approver for department: {department}")
                else:
                    app.logger.warning(f"[PO Update] Could not find PR data for PR: {pr_number}")
            else:
                app.logger.warning(f"[PO Update] Missing PR number or DATA_FILE not found")
                
        except Exception as e:
            app.logger.exception(f"[PO Update] Failed to send re-approval emails: {e}")
            # Don't fail the update if email sending fails
        
        flash(f"PO {po_number} has been updated and sent for re-approval")
        return redirect(url_for('po_system'))
        
    except Exception as e:
        app.logger.exception(f"Error updating PO: {e}")
        flash("Error updating PO. Please try again.")
        return redirect(url_for('po_system'))

@app.route('/download_additional_docs')
@require_auth
def download_additional_docs():
    """Download additional documents for a PO as a ZIP file"""
    po = sanitize_input(request.args.get('po', '').strip())
    
    if not po:
        return jsonify({'error': 'PO number is required'}), 400
    
    try:
        # Check if PO exists and is approved
        df_po = pd.read_excel(EXCEL_FILE, dtype=str).fillna('')
        df_po['PO Number'] = df_po['PO Number'].str.strip()
        po_row = df_po[df_po['PO Number'] == po]
        
        if po_row.empty:
            return jsonify({'error': f'PO {po} not found'}), 404
        
        po_status = po_row['PO Status'].iloc[0].strip().lower()
        if po_status != 'approved':
            return jsonify({'error': f'PO {po} is not approved yet'}), 403
        
        # Check if additional documents folder exists
        additional_docs_folder = os.path.join(BASE_DIR, "additional_documents", po)
        
        if not os.path.exists(additional_docs_folder):
            return jsonify({'error': f'No additional documents found for PO {po}'}), 404
        
        # Get all files in the additional documents folder
        additional_files = []
        for filename in os.listdir(additional_docs_folder):
            file_path = os.path.join(additional_docs_folder, filename)
            if os.path.isfile(file_path):
                additional_files.append((filename, file_path))
        
        if not additional_files:
            return jsonify({'error': f'No additional documents found for PO {po}'}), 404
        
        # Create ZIP file in memory
        from io import BytesIO
        
        zip_buffer = BytesIO()
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for filename, file_path in additional_files:
                zip_file.write(file_path, filename)
        
        zip_buffer.seek(0)
        
        # Return ZIP file
        return send_file(
            zip_buffer,
            as_attachment=True,
            download_name=f'{po}_Additional_Documents.zip',
            mimetype='application/zip'
        )
        
    except Exception as e:
        app.logger.error(f"Error downloading additional documents for PO {po}: {e}")
        return jsonify({'error': 'Failed to download additional documents'}), 500

@app.route('/download_saved_po')
@require_auth
def download_saved_po():
    po = sanitize_input(request.args.get('po', '').strip())
    if not po:
        return "Missing PO number", 400

    fname = f"{po}.docx"
    path  = os.path.join(PURCHASE_ORDER_FOLDER, fname)
    if not os.path.exists(path):
        return "PO not found", 404

    return send_from_directory(PURCHASE_ORDER_FOLDER, fname, as_attachment=True)

@app.route('/api/dashboard_stats')
@require_auth
def dashboard_stats():
    total_pos = 0
    total_value = 0.0
    pending_approvals = 0
    completed = 0

    if os.path.exists(EXCEL_FILE):
        try:
            df_po = load_po_df() # Use the updated helper function (already deduplicated)
            if not df_po.empty:
                total_pos = len(df_po)  # Now correctly counts unique POs
                
                # Calculate total value excluding rejected POs
                # Filter out rejected POs before calculating total value
                df_approved = df_po[df_po['PO Status'].str.lower().str.strip().fillna('') != 'rejected']
                total_value = df_approved['Budget Spend'].sum() if 'Budget Spend' in df_approved.columns else 0.0
                
                app.logger.info(f"Dashboard stats - Total POs: {total_pos}, Approved POs: {len(df_approved)}, Total Value (excluding rejected): {total_value:,.2f}")
        except Exception as e:
            app.logger.error(f"Error reading PO_data.xlsx for stats: {e}")

    pending_po = 0
    completed_po = 0
    if os.path.exists(EXCEL_FILE):
        try:
            # Use the same deduplicated data for consistency
            df_po = load_po_df()
            if 'PO Status' in df_po.columns and not df_po.empty:
                po_status = df_po['PO Status'].str.lower().str.strip().fillna('')
                pending_po = (po_status == 'pending').sum()
                completed_po = (po_status == 'approved').sum()
        except Exception as e:
            app.logger.error(f"Error reading PO status for stats: {e}")

    # Only count PO pending approvals, not PR pending approvals
    pending_approvals = int(pending_po)
    completed = int(completed_po)

    return jsonify({
        'total_pos': int(total_pos),
        'pending_approvals': int(pending_approvals),
        'completed': int(completed),
        'total_value': f"{total_value:,.2f}"
    })


#  ─── API ENDPOINTS FOR PROCORE INTEGRATION ──────────────────────────────────

@app.route('/api/v1/project-budgets', methods=['GET'])
@require_api_key
def get_project_budgets():
    """
    Get budget information for all projects or a specific project using project-specific budget files
    Query parameters:
    - project_number: Optional filter for specific project
    """
    try:
        project_number_filter = request.args.get('project_number', '').strip()
        
        # Load PR data to get project list
        df_pr = pd.read_excel(DATA_FILE, dtype=str).fillna('')
        
        # Group by project
        if not df_pr.empty:
            df_pr['Indicative Price'] = pd.to_numeric(df_pr['Indicative Price'], errors='coerce').fillna(0)
            
            if project_number_filter:
                # Filter for specific project
                df_filtered = df_pr[df_pr['Project Number'].str.strip().str.lower() == project_number_filter.lower()]
                if df_filtered.empty:
                    return jsonify({
                        'error': 'Project not found',
                        'message': f'No data found for project number: {project_number_filter}'
                    }), 404
                
                project_number = str(project_number_filter).strip()
                project_name = df_filtered['Project Name'].iloc[0] if not df_filtered.empty else ''
                
                # Try to load from project-specific budget file first
                budget_data = load_project_budget_data(project_number)
                
                if budget_data:
                    project_data = {
                        'project_name': project_name,
                        'project_number': project_number,
                        'total_project_budget': float(budget_data['total_budget']),
                        'budget_source': 'project_file',
                        'budget_file': budget_data['budget_file'],
                        'material_budget': float(budget_data['material_budget']),
                        'service_budget': float(budget_data['service_budget'])
                    }
                else:
                    # Fallback to PR data
                    project_budget = df_filtered['Indicative Price'].sum()
                    project_data = {
                        'project_name': project_name,
                        'project_number': project_number,
                        'total_project_budget': float(project_budget),
                        'budget_source': 'pr_data',
                        'budget_file': None,
                        'material_budget': 0,
                        'service_budget': 0
                    }
                    
                    # Add notification for missing budget file
                    add_budget_notification(project_number)
                
                return jsonify(project_data)
            else:
                # Return all projects
                projects_summary = []
                total_budget_all_projects = 0
                
                for project_number in df_pr['Project Number'].dropna().unique():
                    project_number = str(project_number).strip()
                    project_data = df_pr[df_pr['Project Number'] == project_number]
                    project_name = project_data['Project Name'].iloc[0] if not project_data.empty else ''
                    
                    # Try to load from project-specific budget file first
                    budget_data = load_project_budget_data(project_number)
                    
                    if budget_data:
                        project_budget = float(budget_data['total_budget'])
                        projects_summary.append({
                            'project_name': project_name,
                            'project_number': project_number,
                            'total_project_budget': project_budget,
                            'budget_source': 'project_file',
                            'budget_file': budget_data['budget_file']
                        })
                        total_budget_all_projects += project_budget
                    else:
                        # Fallback to PR data
                        project_budget = project_data['Indicative Price'].sum()
                        projects_summary.append({
                            'project_name': project_name,
                            'project_number': project_number,
                            'total_project_budget': float(project_budget),
                            'budget_source': 'pr_data',
                            'budget_file': None
                        })
                        total_budget_all_projects += float(project_budget)
                        
                        # Add notification for missing budget file
                        add_budget_notification(project_number)
                
                return jsonify({
                    'projects': projects_summary,
                    'total_budget_all_projects': float(total_budget_all_projects)
                })
        else:
            return jsonify({
                'projects': [],
                'total_budget_all_projects': 0
            })
            
    except Exception as e:
        app.logger.error(f"Error in get_project_budgets: {str(e)}")
        return jsonify({'error': 'Internal server error', 'message': str(e)}), 500

@app.route('/api/v1/project-expenditures', methods=['GET'])
@require_api_key
def get_project_expenditures():
    """
    Get expenditure information for all projects or a specific project
    Query parameters:
    - project_number: Optional filter for specific project
    """
    try:
        project_number_filter = request.args.get('project_number', '').strip()
        
        # Load data.xlsx (expenditure data)
        if not os.path.exists(DATA_FILE):
            return jsonify({'projects': [], 'total_expenditure': 0})
            
        df_data = pd.read_excel(DATA_FILE, dtype=str).fillna('')
        
        if df_data.empty:
            return jsonify({'projects': [], 'total_expenditure': 0})
            
        # Convert Indicative Price to numeric for expenditure calculation
        df_data['Indicative Price'] = pd.to_numeric(df_data['Indicative Price'], errors='coerce').fillna(0)
        
        if project_number_filter:
            # Filter for specific project
            df_filtered = df_data[df_data['Project Number'].str.strip().str.lower() == project_number_filter.lower()]
            if df_filtered.empty:
                return jsonify({
                    'error': 'Project not found',
                    'message': f'No expenditure data found for project number: {project_number_filter}'
                }), 404
            
            total_expenditure = df_filtered['Indicative Price'].sum()
            pr_count = len(df_filtered)
            
            # Get detailed PR breakdown
            pr_details = []
            for _, row in df_filtered.iterrows():
                pr_details.append({
                    'pr_number': str(row['PR Number']),
                    'department': str(row['Requisition Department']),
                    'discipline': str(row['Discipline']),
                    'item_name': str(row['Item Name']),
                    'item_description': str(row['Item Description']),
                    'amount': float(row['Indicative Price']),
                    'date': str(row['Date']),
                    'requester': str(row['Name'])
                })
            
            return jsonify({
                'project_name': df_filtered['Project Name'].iloc[0] if not df_filtered.empty else '',
                'project_number': project_number_filter,
                'total_expenditure': float(total_expenditure),
                'pr_count': int(pr_count),
                'purchase_requisitions': pr_details
            })
        else:
            # Return expenditures for all projects
            projects_expenditure = []
            for project_number in df_data['Project Number'].dropna().unique():
                project_data = df_data[df_data['Project Number'] == project_number]
                total_expenditure = project_data['Indicative Price'].sum()
                pr_count = len(project_data)
                
                projects_expenditure.append({
                    'project_name': project_data['Project Name'].iloc[0] if not project_data.empty else '',
                    'project_number': str(project_number).strip(),
                    'total_expenditure': float(total_expenditure),
                    'pr_count': int(pr_count)
                })
            
            return jsonify({
                'projects': projects_expenditure,
                'total_expenditure': float(df_data['Indicative Price'].sum())
            })
            
    except Exception as e:
        app.logger.error(f"Error in get_project_expenditures: {str(e)}")
        return jsonify({'error': 'Internal server error', 'message': str(e)}), 500

@app.route('/api/v1/project-financial-summary', methods=['GET'])
@require_api_key
def get_project_financial_summary():
    """
    Get complete financial summary for a project including budgets, expenditures, and remaining budget
    Query parameters:
    - project_number: Required project number filter
    """
    try:
        project_number = request.args.get('project_number', '').strip()
        
        if not project_number:
            return jsonify({'error': 'project_number parameter is required'}), 400
        
        # Initialize response data
        financial_summary = {
            'project_name': '',
            'project_number': project_number,
            'budget_data': {
                'total_budget_allocated': 0,
                'material_budget': 0,
                'service_budget': 0
            },
            'expenditure_data': {
                'total_spent': 0,
                'po_count': 0,
                'approved_pos': 0,
                'pending_pos': 0
            },
            'remaining_budget': 0,
            'budget_utilization_percentage': 0
        }
        
        # Get project-specific budget from budget file
        budget_data = load_project_budget_data(project_number)
        if budget_data:
            financial_summary['budget_data']['material_budget'] = float(budget_data['material_budget'])
            financial_summary['budget_data']['service_budget'] = float(budget_data['service_budget'])
            financial_summary['budget_data']['total_budget_allocated'] = float(budget_data['total_budget'])
            financial_summary['budget_source'] = 'project_file'
        else:
            # No fallback to department budgets - use 0 if project file not found
            financial_summary['budget_data']['material_budget'] = 0
            financial_summary['budget_data']['service_budget'] = 0
            financial_summary['budget_data']['total_budget_allocated'] = 0
            financial_summary['budget_source'] = 'no_file'
            
            # Add notification for missing budget file
            add_budget_notification(project_number)
        
        # Get project name from data.xlsx
        if os.path.exists(DATA_FILE):
            df_data = pd.read_excel(DATA_FILE, dtype=str).fillna('')
            project_data = df_data[df_data['Project Number'].str.strip().str.lower() == project_number.lower()]
            if not project_data.empty:
                financial_summary['project_name'] = str(project_data['Project Name'].iloc[0])
        
        # Get expenditure data from data.xlsx (not from PO_data.xlsx)
        if os.path.exists(DATA_FILE):
            df_data = pd.read_excel(DATA_FILE, dtype=str).fillna('')
            df_data['Indicative Price'] = pd.to_numeric(df_data['Indicative Price'], errors='coerce').fillna(0)
            
            project_data = df_data[df_data['Project Number'].str.strip().str.lower() == project_number.lower()]
            if not project_data.empty:
                total_spent = project_data['Indicative Price'].sum()
                pr_count = len(project_data)
                
                financial_summary['expenditure_data'] = {
                    'total_spent': float(total_spent),
                    'pr_count': int(pr_count),
                    'approved_prs': int(pr_count),  # All PRs are considered approved for expenditure calculation
                    'pending_prs': 0
                }
        
        # Calculate remaining budget and utilization
        total_budget = financial_summary['budget_data']['total_budget_allocated']
        total_spent = financial_summary['expenditure_data']['total_spent']
        
        financial_summary['remaining_budget'] = float(total_budget - total_spent)
        
        if total_budget > 0:
            financial_summary['budget_utilization_percentage'] = float((total_spent / total_budget) * 100)
        
        # Check if project exists
        if financial_summary['project_name'] == '' and financial_summary['expenditure_data']['po_count'] == 0:
            return jsonify({
                'error': 'Project not found',
                'message': f'No financial data found for project number: {project_number}'
            }), 404
        
        return jsonify(financial_summary)
        
    except Exception as e:
        app.logger.error(f"Error in get_project_financial_summary: {str(e)}")
        return jsonify({'error': 'Internal server error', 'message': str(e)}), 500

@app.route('/api/v1/projects', methods=['GET'])
@require_api_key
def get_all_projects():
    """
    Get list of all projects with basic information
    """
    try:
        projects = []
        project_names = set()
        
        # Get projects from PR data
        if os.path.exists(DATA_FILE):
            df_pr = pd.read_excel(DATA_FILE, dtype=str).fillna('')
            for _, row in df_pr.iterrows():
                project_name = str(row.get('Project Name', '')).strip()
                project_number = str(row.get('Project Number', '')).strip()
                if project_name and project_name not in project_names:
                    projects.append({
                        'project_name': project_name,
                        'project_number': project_number
                    })
                    project_names.add(project_name)
        
        # Get additional projects from PO data that might not be in PR data
        if os.path.exists(EXCEL_FILE):
            df_po = pd.read_excel(EXCEL_FILE, dtype=str).fillna('')
            for _, row in df_po.iterrows():
                project_name = str(row.get('Project Name', '')).strip()
                project_number = str(row.get('Project Number', '')).strip()
                if project_name and project_name not in project_names:
                    projects.append({
                        'project_name': project_name,
                        'project_number': project_number
                    })
                    project_names.add(project_name)
        
        # Sort projects by name
        projects.sort(key=lambda x: x['project_name'])
        
        return jsonify({
            'projects': projects,
            'total_projects': len(projects)
        })
        
    except Exception as e:
        app.logger.error(f"Error in get_all_projects: {str(e)}")
        return jsonify({'error': 'Internal server error', 'message': str(e)}), 500

#  ─── API KEY MANAGEMENT ENDPOINTS ───────────────────────────────────────────

@app.route('/api/admin/create-api-key', methods=['POST'])
def admin_create_api_key():
    """Admin endpoint to create new API keys (requires web login)"""
    if not session.get('logged_in'):
        return jsonify({'error': 'Unauthorized', 'message': 'Admin login required'}), 401
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Bad request', 'message': 'JSON data required'}), 400
    
    name = data.get('name', '').strip()
    description = data.get('description', '').strip()
    
    if not name:
        return jsonify({'error': 'Bad request', 'message': 'API key name is required'}), 400
    
    try:
        api_key = create_api_key(name, description)
        return jsonify({
            'success': True,
            'api_key': api_key,
            'name': name,
            'description': description,
            'message': 'API key created successfully. Save this key securely - it will not be shown again!'
        })
    except Exception as e:
        app.logger.error(f"Error creating API key: {str(e)}")
        return jsonify({'error': 'Internal server error', 'message': str(e)}), 500

@app.route('/api/admin/list-api-keys', methods=['GET'])
def admin_list_api_keys():
    """Admin endpoint to list all API keys (without revealing the actual keys)"""
    if not session.get('logged_in'):
        return jsonify({'error': 'Unauthorized', 'message': 'Admin login required'}), 401
    
    try:
        api_keys = load_api_keys()
        keys_info = []
        
        for key_hash, key_data in api_keys.items():
            keys_info.append({
                'name': key_data.get('name', 'Unknown'),
                'description': key_data.get('description', ''),
                'created_at': key_data.get('created_at', ''),
                'last_used': key_data.get('last_used', 'Never'),
                'active': key_data.get('active', False),
                'key_hash': key_hash[:8] + '...'  # Show only first 8 chars of hash
            })
        
        return jsonify({
            'api_keys': keys_info,
            'total_keys': len(keys_info)
        })
    except Exception as e:
        app.logger.error(f"Error listing API keys: {str(e)}")
        return jsonify({'error': 'Internal server error', 'message': str(e)}), 500

# Add these functions after the existing imports and before the init_excel function

def convert_project_number_to_filename(project_number):
    """
    Convert project number to budget filename format
    Example: "I2501F001" -> "I2501F001_budget.xlsx"
    """
    if not project_number:
        return None
    
    # Add _budget.xlsx suffix to project number
    filename = project_number + '_budget.xlsx'
    return filename

def get_project_budget_file_path(project_number):
    """
    Get the full path to a project's budget file.
    Includes logging to help debug path issues.
    """
    if not project_number:
        return None
    
    filename = convert_project_number_to_filename(project_number)
    if not filename:
        return None
    
    # Construct the absolute path
    file_path = os.path.join(BASE_DIR, filename)
    
    # Log the path we are checking for debugging purposes
    app.logger.info(f"Checking for budget file at: {file_path}")
    
    # Check if the file exists at the constructed path
    if os.path.exists(file_path):
        app.logger.info(f"Success: Found budget file for project {project_number}.")
        return file_path
    else:
        app.logger.warning(f"Warning: Budget file not found for project {project_number} at path {file_path}.")
        return None

def get_department_approver_email(department):
    """Get the approver email for a given department"""
    try:
        if not department:
            app.logger.warning(f"Department is empty or None")
            return None
        
        app.logger.info(f"Looking for approver email for department: '{department}'")
        
        # Load department emails
        dept_email_df = pd.read_excel(DEPT_EMAIL_FILE, dtype=str).fillna('')
        dept_email_df['Department'] = dept_email_df['Department'].astype(str)
        
        app.logger.info(f"Available departments in email file: {list(dept_email_df['Department'].str.strip())}")
        
        # Find matching department - try exact match first
        match = dept_email_df[dept_email_df['Department'].str.strip().str.lower() == department.lower()]
        
        # If no exact match, try partial matching for common variations
        if match.empty:
            department_lower = department.lower()
            if 'ceo' in department_lower:
                match = dept_email_df[dept_email_df['Department'].str.strip().str.lower().str.contains('ceo')]
            elif 'cfo' in department_lower:
                match = dept_email_df[dept_email_df['Department'].str.strip().str.lower().str.contains('cfo')]
            elif 'procurement' in department_lower:
                match = dept_email_df[dept_email_df['Department'].str.strip().str.lower().str.contains('procurement')]
            elif 'engineering' in department_lower:
                match = dept_email_df[dept_email_df['Department'].str.strip().str.lower().str.contains('engineering')]
            elif 'project' in department_lower:
                match = dept_email_df[dept_email_df['Department'].str.strip().str.lower().str.contains('project')]
            elif 'planning' in department_lower:
                match = dept_email_df[dept_email_df['Department'].str.strip().str.lower().str.contains('planning')]
            elif 'mechanical' in department_lower:
                match = dept_email_df[dept_email_df['Department'].str.strip().str.lower().str.contains('mechanical')]
            elif 'site' in department_lower:
                match = dept_email_df[dept_email_df['Department'].str.strip().str.lower().str.contains('site')]
        
        app.logger.info(f"Department match found: {not match.empty}")
        
        if not match.empty:
            email = match.iloc[0]['Email'].strip()
            app.logger.info(f"Found approver email: {email}")
            return email
        else:
            app.logger.warning(f"No email found for department: '{department}'")
            return None
            
    except Exception as e:
        app.logger.error(f"Error getting department approver email for '{department}': {e}")
        return None

def load_project_budget_data(project_number):
    """
    Load budget data from project-specific budget file
    Returns budget data dict or None if file doesn't exist
    """
    file_path = get_project_budget_file_path(project_number)
    if not file_path:
        return None
    
    try:
        # Load the project-specific budget file
        df = pd.read_excel(file_path, dtype=str).fillna('')
        
        # Calculate budget totals
        total_material_budget = 0
        total_service_budget = 0
        total_budget = 0
        budget_breakdown = {}
        
        # Process budget data based on actual file structure
        if 'Material_Budget' in df.columns and 'Service_Budget' in df.columns:
            # Convert to numeric, handling any non-numeric values
            df['Material_Budget'] = pd.to_numeric(df['Material_Budget'], errors='coerce').fillna(0)
            df['Service_Budget'] = pd.to_numeric(df['Service_Budget'], errors='coerce').fillna(0)
            
            total_material_budget = df['Material_Budget'].sum()
            total_service_budget = df['Service_Budget'].sum()
            total_budget = total_material_budget + total_service_budget
            
            # Create breakdown by department
            for _, row in df.iterrows():
                department = str(row.get('Department', 'Unknown')).strip()
                if department and department != 'nan':
                    budget_breakdown[department] = {
                        'material_budget': float(row['Material_Budget']),
                        'service_budget': float(row['Service_Budget']),
                        'total_budget': float(row['Material_Budget'] + row['Service_Budget'])
                    }
        
        return {
            'project_number': project_number,
            'total_budget': total_budget,
            'material_budget': total_material_budget,
            'service_budget': total_service_budget,
            'budget_breakdown': budget_breakdown,
            'budget_file': convert_project_number_to_filename(project_number),
            'file_exists': True
        }
        
    except Exception as e:
        app.logger.error(f"Error loading budget data for {project_number}: {str(e)}")
        return None

def add_budget_notification(project_number):
    """
    Add notification for missing budget file
    """
    notification_text = f"This Project has not been alloted budget till now, Please contact Financial Team!"
    add_notification('alert-triangle', notification_text, f'/po_system?project={project_number}')

def check_project_budget_exists(project_number):
    """
    Check if budget file exists for a project
    Returns True if exists, False otherwise
    """
    return get_project_budget_file_path(project_number) is not None

# Add this new endpoint after the existing API endpoints

@app.route('/api/v1/project-budget-status', methods=['GET'])
@require_api_key
def get_project_budget_status():
    """
    Check if a project has a dedicated budget file
    Query parameters:
    - project_number: Required project number to check
    """
    try:
        project_number = request.args.get('project_number', '').strip()
        
        if not project_number:
            return jsonify({
                'error': 'Bad request',
                'message': 'project_number parameter is required'
            }), 400
        
        # Check if budget file exists
        budget_file_path = get_project_budget_file_path(project_number)
        budget_exists = budget_file_path is not None
        
        response_data = {
            'project_number': project_number,
            'budget_file_exists': budget_exists,
            'budget_file_path': budget_file_path,
            'expected_filename': convert_project_number_to_filename(project_number)
        }
        
        if budget_exists:
            # Try to load budget data
            budget_data = load_project_budget_data(project_number)
            if budget_data:
                response_data['total_budget'] = budget_data['total_budget']
                response_data['budget_breakdown'] = budget_data['budget_breakdown']
                response_data['budget_source'] = 'project_file'
            else:
                response_data['budget_source'] = 'file_exists_but_error_loading'
        else:
            response_data['budget_source'] = 'not_found'
            # Add notification for missing budget file
            add_budget_notification(project_number)
        
        return jsonify(response_data)
        
    except Exception as e:
        app.logger.error(f"Error in get_project_budget_status: {str(e)}")
        return jsonify({'error': 'Internal server error', 'message': str(e)}), 500

@app.route('/api/v1/project-details', methods=['GET'])
def get_project_details():
    """
    Get project details by project number - no API key required for internal use
    """
    project_number = request.args.get('project_number', '').strip()
    
    if not project_number:
        return jsonify({
            'error': 'Bad request',
            'message': 'project_number parameter is required'
        }), 400
    
    try:
        # Load PR data to find project details
        if os.path.exists(DATA_FILE):
            df_pr = pd.read_excel(DATA_FILE, dtype=str).fillna('')
            project_data = df_pr[df_pr['Project Number'].str.strip().str.lower() == project_number.lower()]
            
            if not project_data.empty:
                project_name = str(project_data['Project Name'].iloc[0]).strip()
                return jsonify({
                    'project_number': project_number,
                    'project_name': project_name,
                    'found': True
                })
        
        # If not found in PR data, check PO data (only if it has Project Number column)
        if os.path.exists(EXCEL_FILE):
            df_po = pd.read_excel(EXCEL_FILE, dtype=str).fillna('')
            if 'Project Number' in df_po.columns and 'Project Name' in df_po.columns:
                project_data = df_po[df_po['Project Number'].str.strip().str.lower() == project_number.lower()]
                
                if not project_data.empty:
                    project_name = str(project_data['Project Name'].iloc[0]).strip()
                    return jsonify({
                        'project_number': project_number,
                        'project_name': project_name,
                        'found': True
                    })
        
        # Project not found
        return jsonify({
            'project_number': project_number,
            'project_name': '',
            'found': False,
            'message': 'Project not found'
        }), 404
        
    except Exception as e:
        app.logger.error(f"Error getting project details: {str(e)}")
        return jsonify({
            'error': 'Failed to get project details',
            'message': str(e)
        }), 500

def sync_admin_credentials():
    """Automatically sync admin credentials from environment variables to database"""
    try:
        env_email = os.getenv('ADMIN_EMAIL')
        env_password = os.getenv('ADMIN_PASSWORD')
        
        if not env_email or not env_password:
            print("⚠️  ADMIN_EMAIL or ADMIN_PASSWORD not set in environment variables")
            return
        
        # Get current admin user from database
        conn = db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT id, email, password_hash FROM users WHERE role = "Admin" LIMIT 1')
        admin_user = cursor.fetchone()
        
        if admin_user:
            admin_id, db_email, db_password_hash = admin_user
            
            # Check if credentials need updating
            if db_email != env_email or not db.verify_password(env_password, db_password_hash):
                print(f"🔄 Updating admin credentials from environment variables...")
                print(f"   Old email: {db_email}")
                print(f"   New email: {env_email}")
                
                # Update credentials
                new_password_hash = db.hash_password(env_password)
                cursor.execute('''
                    UPDATE users 
                    SET email = ?, password_hash = ? 
                    WHERE id = ?
                ''', (env_email, new_password_hash, admin_id))
                
                conn.commit()
                print(f"✅ Admin credentials updated successfully")
            else:
                print(f"✅ Admin credentials are already in sync")
        else:
            print("⚠️  No admin user found in database")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Error syncing admin credentials: {e}")

def check_env_changes():
    """Check if environment variables have changed and reload if needed"""
    global INITIAL_ADMIN_EMAIL, INITIAL_ADMIN_PASSWORD
    
    try:
        # Reload environment variables
        load_dotenv(override=True)
        
        current_email = os.getenv('ADMIN_EMAIL')
        current_password = os.getenv('ADMIN_PASSWORD')
        
        # Check if values have changed
        if (current_email != INITIAL_ADMIN_EMAIL or 
            current_password != INITIAL_ADMIN_PASSWORD):
            
            print("🔄 Environment variables changed, updating admin credentials...")
            
            # Update stored values
            INITIAL_ADMIN_EMAIL = current_email
            INITIAL_ADMIN_PASSWORD = current_password
            
            # Sync credentials
            sync_admin_credentials()
            
        return True
        
    except Exception as e:
        print(f"❌ Error checking environment changes: {e}")
        return False

@app.route('/documentation')
@require_auth
def documentation():
    """Documentation page showing approval hierarchy and permissions"""
    return render_template('documentation.html')

@app.route('/api/get_po_details/<po_number>')
def get_po_details(po_number):
    """Get PO details for display on approval page"""
    try:
        df_po = pd.read_excel(EXCEL_FILE, dtype=str).fillna('')
        po_row = df_po[df_po['PO Number'] == po_number]
        
        if po_row.empty:
            return jsonify({'error': 'PO not found'}), 404
        
        po_data = po_row.iloc[0]
        
        # Get PR details for additional context
        df_pr = pd.read_excel(DATA_FILE, dtype=str).fillna('')
        pr_row = df_pr[df_pr['PR Number'] == po_data['PR Number']]
        
        pr_data = pr_row.iloc[0] if not pr_row.empty else {}
        
        return jsonify({
            'po_number': po_data['PO Number'],
            'project_name': po_data['Project Name'],
            'project_number': po_data['Project Number'],
            'company': po_data['Company Name'],
            'total_amount': po_data['Total Amount'],
            'basic_amount': po_data['Basic Amount'],
            'pf_amount': po_data['PF Charges'],
            'gst_amount': po_data['GST Amount'],
            'freight_amount': po_data['Freight Charges'],
            'other_amount': po_data['Other Charges'],
            'pr_number': po_data['PR Number'],
            'requester_dept': pr_data.get('Requisition Department', 'N/A'),
            'discipline': pr_data.get('Discipline', 'N/A')
        })
    except Exception as e:
        app.logger.error(f"Error getting PO details: {e}")
        return jsonify({'error': 'Failed to get PO details'}), 500

@app.route('/api/get_pr_details/<pr_number>')
def get_pr_details(pr_number):
    """Get PR details for display on approval page"""
    try:
        df_pr = pd.read_excel(DATA_FILE, dtype=str).fillna('')
        pr_row = df_pr[df_pr['PR Number'] == pr_number]
        
        if pr_row.empty:
            return jsonify({'error': 'PR not found'}), 404
        
        pr_data = pr_row.iloc[0]
        
        return jsonify({
            'pr_number': pr_data['PR Number'],
            'project_name': pr_data['Project Name'],
            'project_number': pr_data['Project Number'],
            'department': pr_data['Requisition Department'],
            'requester': pr_data['Name'],
            'requester_email': pr_data['Requester Email'],
            'discipline': pr_data.get('Discipline', 'N/A'),
            'status': pr_data.get('PR Status', 'N/A'),
            'order_type': pr_data.get('Order Type', ''),
            'item_type': pr_data.get('Item Type', '')
        })
    except Exception as e:
        app.logger.error(f"Error getting PR details: {e}")
        return jsonify({'error': 'Failed to get PR details'}), 500

if __name__ == '__main__':
    # Initialize database
    try:
        db.init_database()
        print("Database initialized successfully")
        
        # Automatically sync admin credentials
        sync_admin_credentials()
        
    except Exception as e:
        print(f"Error initializing database: {e}")
    
    app.run(debug=False, host='0.0.0.0', port=5000)
