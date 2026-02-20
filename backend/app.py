from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import json
import re
import time
import requests
import uuid
import hmac
import hashlib
from cryptography.fernet import Fernet
import stripe
from authlib.integrations.flask_client import OAuth
import redis

app = Flask(__name__)
# app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
# app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///gifts.db')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-change-in-production')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=7)

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
# CORS(app, origins=[os.environ.get('FRONTEND_URL', 'http://localhost:5173')], supports_credentials=True)
CORS(app, origins=[os.environ.get('FRONTEND_URL')], supports_credentials=True)

# Redis for rate limiting and caching
redis_url = os.environ.get('REDIS_URL')
redis_client = None
if redis_url and redis_url.strip():
    try:
        redis_client = redis.from_url(redis_url)
    except:
        redis_client = None

# Encryption
_enc_key = os.environ.get('ENCRYPTION_KEY')
if not _enc_key:
    _enc_key = Fernet.generate_key()
elif isinstance(_enc_key, str):
    _enc_key = _enc_key.encode()
cipher_suite = Fernet(_enc_key)

# Stripe setup
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET')

# Paystack config
PAYSTACK_SECRET = os.environ.get('PAYSTACK_SECRET_KEY')
PAYSTACK_BASE_URL = "https://api.paystack.co"

# Cloudflare R2 Configuration
R2_ENDPOINT = os.environ.get('R2_ENDPOINT')  # https://<account-id>.r2.cloudflarestorage.com
R2_ACCESS_KEY = os.environ.get('R2_ACCESS_KEY')
R2_SECRET_KEY = os.environ.get('R2_SECRET_KEY')
R2_BUCKET_NAME = os.environ.get('R2_BUCKET_NAME', 'gift-recommender')
R2_PUBLIC_URL = os.environ.get('R2_PUBLIC_URL')  # https://pub-<hash>.r2.dev

# Google OAuth setup
oauth = OAuth(app)
oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# Encryption for API keys (cipher_suite already initialized above)

# Initialize S3 client for R2
s3_client = None
if all([R2_ENDPOINT, R2_ACCESS_KEY, R2_SECRET_KEY]):
    s3_client = boto3.client(
        's3',
        endpoint_url=R2_ENDPOINT,
        aws_access_key_id=R2_ACCESS_KEY,
        aws_secret_access_key=R2_SECRET_KEY,
        region_name='auto'  # R2 uses 'auto'
    )

def ensure_bucket_exists():
    """Create R2 bucket if it doesn't exist"""
    if not s3_client:
        return False
    try:
        s3_client.head_bucket(Bucket=R2_BUCKET_NAME)
        return True
    except:
        try:
            s3_client.create_bucket(Bucket=R2_BUCKET_NAME)
            # Enable public access if needed
            s3_client.put_bucket_cors(
                Bucket=R2_BUCKET_NAME,
                CORSConfiguration={
                    'CORSRules': [
                        {
                            'AllowedOrigins': ['*'],
                            'AllowedMethods': ['GET', 'PUT', 'POST', 'DELETE'],
                            'AllowedHeaders': ['*'],
                            'MaxAgeSeconds': 3600
                        }
                    ]
                }
            )
            return True
        except Exception as e:
            print(f"Failed to create bucket: {e}")
            return False

def upload_chat_file(file_data, user_id, original_filename, analysis_id=None):
    """
    Upload chat file to R2
    Returns: (success: bool, file_url: str, error_message: str)
    """
    if not s3_client:
        return False, None, "R2 not configured"
    
    try:
        # Generate unique key
        file_ext = original_filename.rsplit('.', 1)[-1] if '.' in original_filename else 'txt'
        r2_key = f"users/{user_id}/chats/{uuid.uuid4()}.{file_ext}"
        
        # Upload to R2
        s3_client.put_object(
            Bucket=R2_BUCKET_NAME,
            Key=r2_key,
            Body=file_data,
            ContentType='text/plain',
            Metadata={
                'user-id': str(user_id),
                'original-filename': original_filename,
                'analysis-id': str(analysis_id) if analysis_id else ''
            }
        )
        
        # Generate public URL
        if R2_PUBLIC_URL:
            file_url = f"{R2_PUBLIC_URL}/{r2_key}"
        else:
            # Generate presigned URL (valid for 1 hour)
            file_url = s3_client.generate_presigned_url(
                'get_object',
                Params={'Bucket': R2_BUCKET_NAME, 'Key': r2_key},
                ExpiresIn=3600
            )
        
        return True, file_url, None
        
    except Exception as e:
        return False, None, str(e)

def delete_chat_file(r2_key):
    """Delete file from R2"""
    if not s3_client:
        return False
    
    try:
        s3_client.delete_object(Bucket=R2_BUCKET_NAME, Key=r2_key)
        return True
    except Exception as e:
        print(f"Failed to delete file: {e}")
        return False

def get_file_content(r2_key):
    """Retrieve file content from R2"""
    if not s3_client:
        return None
    
    try:
        response = s3_client.get_object(Bucket=R2_BUCKET_NAME, Key=r2_key)
        return response['Body'].read().decode('utf-8')
    except Exception as e:
        print(f"Failed to get file: {e}")
        return None

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    google_id = db.Column(db.String(255), unique=True)
    name = db.Column(db.String(255))
    avatar = db.Column(db.String(500))
    
    # API Keys (encrypted)
    brave_api_key = db.Column(db.Text)
    # gemini_api_key = db.Column(db.Text)
    nvidia_api_key = db.Column(db.Text)

    # Paystack
    paystack_customer_code = db.Column(db.String(255))
    paystack_subscription_code = db.Column(db.String(255))
    
    # Stripe
    stripe_customer_id = db.Column(db.String(255))
    subscription_status = db.Column(db.String(50), default='free')  # free, active, canceled
    subscription_tier = db.Column(db.String(50), default='free')   # free, pro, enterprise
    subscription_end_date = db.Column(db.DateTime)
    
    # Usage tracking
    monthly_searches = db.Column(db.Integer, default=0)
    search_reset_date = db.Column(db.DateTime)
    total_analyses = db.Column(db.Integer, default=0)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_active = db.Column(db.DateTime, default=datetime.utcnow)
    
    analyses = db.relationship('Analysis', backref='user', lazy=True, cascade='all, delete-orphan')

class Analysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_name = db.Column(db.String(100))
    location = db.Column(db.String(100))
    budget = db.Column(db.String(50))
    currency = db.Column(db.String(10))
    chat_log = db.Column(db.Text)
    pain_points = db.Column(db.Text)
    recommendations = db.Column(db.Text)
    search_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ChatFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    analysis_id = db.Column(db.Integer, db.ForeignKey('analysis.id'), nullable=True)
    original_filename = db.Column(db.String(255))
    r2_key = db.Column(db.String(500), unique=True)  # Path in R2 bucket
    r2_url = db.Column(db.String(1000))  # Public or presigned URL
    file_size = db.Column(db.Integer)  # Bytes
    mime_type = db.Column(db.String(100))
    is_processed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    analysis = db.relationship('Analysis', backref='chat_file')

# Encryption helpers
def encrypt_key(key):
    if not key:
        return None
    return cipher_suite.encrypt(key.encode()).decode()

def decrypt_key(encrypted_key):
    if not encrypted_key:
        return None
    try:
        return cipher_suite.decrypt(encrypted_key.encode()).decode()
    except:
        return None

# Rate limiting
def check_rate_limit(user_id, tier='free'):
    """Rate limiting using database - no Redis required"""
    user = User.query.get(user_id)
    if not user:
        return True, 0
    
    # Reset monthly count if new month
    now = datetime.utcnow()
    if user.search_reset_date:
        if user.search_reset_date.month != now.month or user.search_reset_date.year != now.year:
            user.monthly_searches = 0
            user.search_reset_date = now
            db.session.commit()
    else:
        user.search_reset_date = now
        db.session.commit()
    
    limits = {'free': 50, 'pro': 500, 'enterprise': 5000}
    limit = limits.get(tier, 50)
    
    if user.monthly_searches >= limit:
        # Calculate seconds until next month
        next_month = datetime(now.year + (now.month // 12), ((now.month % 12) + 1), 1)
        retry_after = int((next_month - now).total_seconds())
        return False, retry_after
    
    return True, 0
    
# Search and Analysis Classes
class BraveSearch:
    def __init__(self, api_key):
        self.api_key = api_key
        self.endpoint = "https://api.search.brave.com/res/v1/web/search"
        
    def search(self, query, max_results=4):
        if not self.api_key:
            return []
        headers = {"X-Subscription-Token": self.api_key, "Accept": "application/json"}
        params = {"q": query, "count": max_results, "search_lang": "en"}
        try:
            response = requests.get(self.endpoint, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return [{"title": r.get("title", ""), "href": r.get("url", ""), 
                        "body": r.get("description", "")} for r in data.get("web", {}).get("results", [])]
            return []
        except Exception as e:
            print(f"Search error: {e}")
            return []

# class GeminiClient:
    # def __init__(self, api_key):
        # self.api_key = api_key
        # self.url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
        
    # def generate(self, prompt):
        # time.sleep(0.5)  # Rate limiting
        # data = {
            # "contents": [{"parts": [{"text": prompt}]}],
            # "safetySettings": [{"category": c, "threshold": "BLOCK_NONE"} 
                              # for c in ["HARM_CATEGORY_HARASSMENT", "HARM_CATEGORY_HATE_SPEECH",
                                       # "HARM_CATEGORY_SEXUALLY_EXPLICIT", "HARM_CATEGORY_DANGEROUS_CONTENT"]]
        # }
        # try:
            # response = requests.post(self.url, headers={'Content-Type': 'application/json'}, 
                                   # json=data, timeout=30)
            # if response.status_code == 200 and 'candidates' in response.json():
                # return response.json()['candidates'][0]['content']['parts'][0]['text']
            # return "{}"
        # except Exception as e:
            # print(f"Gemini error: {e}")
            # return "{}"

class KimiClient:
    def __init__(self, api_key):
        self.api_key = api_key
        self.invoke_url = "https://integrate.api.nvidia.com/v1/chat/completions"
        
    def generate(self, prompt):
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json"
        }
        payload = {
            "model": "moonshotai/kimi-k2.5",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 4096,
            "temperature": 0.7,
            "top_p": 0.9,
            "stream": False,
            "chat_template_kwargs": {"thinking": False}
        }
        try:
            response = requests.post(self.invoke_url, headers=headers, json=payload, timeout=60)
            response.raise_for_status()
            data = response.json()
            if 'choices' in data and len(data['choices']) > 0:
                return data['choices'][0]['message']['content']
            return "{}"
        except requests.exceptions.Timeout:
            print("❌ Kimi API timeout")
            return "{}"
        except Exception as e:
            print(f"❌ Kimi API Error: {e}")
            return "{}"

# Paystack helpers
def paystack_request(method, endpoint, data=None):
    headers = {
        'Authorization': f'Bearer {PAYSTACK_SECRET}',
        'Content-Type': 'application/json'
    }
    url = f"{PAYSTACK_BASE_URL}/{endpoint}"
    if method == 'GET':
        response = requests.get(url, headers=headers)
    elif method == 'POST':
        response = requests.post(url, headers=headers, json=data)
    return response.json()

def create_paystack_customer(email, first_name, last_name):
    data = {'email': email, 'first_name': first_name, 'last_name': last_name}
    result = paystack_request('POST', 'customer', data)
    return result.get('data', {}).get('customer_code')

def initialize_transaction(email, amount_kobo, plan_code=None, callback_url=None):
    data = {
        'email': email,
        'amount': amount_kobo,
        'callback_url': callback_url or os.environ.get('FRONTEND_URL') + '/settings?success=true'
    }
    if plan_code:
        data['plan'] = plan_code
    result = paystack_request('POST', 'transaction/initialize', data)
    return result.get('data', {}).get('authorization_url')

class PainPointAnalyzer:
    # def __init__(self, gemini_key):
        # self.gemini = GeminiClient(gemini_key)

    def __init__(self, api_key):
        self.kimi = KimiClient(api_key)
        
    def analyze(self, chat_text, recipient):
        prompt = f"""Analyze this chat for pain points experienced by {recipient}.
Return JSON array with fields: pain_point (string), score (1-10), category (Physical/Emotional/Practical), trigger_text (exact quote), context (brief).
Chat: {chat_text[:4000]}"""
        # resp = self.gemini.generate(prompt)
        resp = self.kimi.generate(prompt)
        try:
            match = re.search(r'\[.*\]', resp.replace("\n", " "), re.DOTALL)
            return json.loads(match.group(0)) if match else []
        except Exception as e:
            print(f"Parse error: {e}")
            return []

class ShoppingAgent:
    # def __init__(self, gemini_key, brave_key):
        # self.gemini = GeminiClient(gemini_key)
    def __init__(self, api_key, brave_key):
        self.kimi = KimiClient(api_key)
        self.search = BraveSearch(brave_key)
        
    def brainstorm(self, pain_point, location):
        prompt = f"""Pain: "{pain_point}". Suggest 3 broad product categories (2-3 words each): practical, splurge, thoughtful.
Return JSON: {{"practical": "...", "splurge": "...", "thoughtful": "..."}}"""
        resp = self.kimi.generate(prompt)
        try:
            match = re.search(r'\{.*\}', resp.replace("\n", " "), re.DOTALL)
            return json.loads(match.group(0)) if match else {"practical": pain_point + " solution"}
        except:
            return {"practical": pain_point + " solution"}
    
    def vet(self, item, results, budget, currency, location):
        prompt = f"""Select best product under {budget} {currency} in {location} from these {len(results)} results: {json.dumps(results[:3])}.
Return JSON: {{"product": "Name", "price_guess": "50", "url": "link", "reason": "Why fits"}} or {{}} if over budget."""
        # resp = self.gemini.generate(prompt)
        resp = self.kimi.generate(prompt)
        try:
            match = re.search(r'\{.*\}', resp.replace("\n", " "), re.DOTALL)
            rec = json.loads(match.group(0)) if match else {}
            if rec.get('product') and rec.get('price_guess'):
                try:
                    if float(rec['price_guess']) <= float(budget):
                        return rec
                except:
                    return rec
        except:
            pass
        return None

# Routes

@app.route('/api/auth/google', methods=['POST'])
def google_auth():
    data = request.get_json()
    token = data.get('token')
    
    # Verify Google token
    try:
        from google.oauth2 import id_token
        from google.auth.transport import requests as google_requests
        
        idinfo = id_token.verify_oauth2_token(token, google_requests.Request())
        
        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            return jsonify({'error': 'Invalid issuer'}), 401
            
        email = idinfo['email']
        google_id = idinfo['sub']
        name = idinfo.get('name', '')
        avatar = idinfo.get('picture', '')
        
        # Find or create user
        user = User.query.filter_by(google_id=google_id).first()
        if not user:
            user = User.query.filter_by(email=email).first()
            if user:
                user.google_id = google_id
            else:
                user = User(
                    email=email,
                    google_id=google_id,
                    name=name,
                    avatar=avatar
                )
                db.session.add(user)
        
        user.last_active = datetime.utcnow()
        db.session.commit()
        
        access_token = create_access_token(identity=user.id)
        
        return jsonify({
            'access_token': access_token,
            'user': {
                'id': user.id,
                'email': user.email,
                'name': user.name,
                'avatar': user.avatar,
                'subscription_tier': user.subscription_tier,
                # 'has_api_keys': bool(user.brave_api_key and user.gemini_api_key),
                'has_api_keys': bool(user.brave_api_key and user.nvidia_api_key)
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 401

@app.route('/api/user/keys', methods=['GET', 'POST'])
@jwt_required()
def user_keys():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if request.method == 'GET':
        # Return masked keys
        brave_masked = '••••' + decrypt_key(user.brave_api_key)[-4:] if user.brave_api_key else None
        # gemini_masked = '••••' + decrypt_key(user.gemini_api_key)[-4:] if user.gemini_api_key else None
        nvidia_masked = '••••' + decrypt_key(user.nvidia_api_key)[-4:] if user.nvidia_api_key else None
        
        return jsonify({
            'brave_api_key': brave_masked,
            # 'gemini_api_key': gemini_masked,
            # 'has_keys': bool(user.brave_api_key and user.gemini_api_key
            'nvidia_api_key': nvidia_masked,
            'has_keys': bool(user.brave_api_key and user.nvidia_api_key)
        })
    
    # POST - update keys
    data = request.get_json()
    brave_key = data.get('brave_api_key', '').strip()
    # gemini_key = data.get('gemini_api_key', '').strip()
    nvidia_key = data.get('nvidia_api_key', '').strip()
    
    # Validate keys    
    if nvidia_key:
        test_client = KimiClient(nvidia_key)
        test_resp = test_client.generate("Say 'test'")
        if not test_resp or test_resp == "{}":
            return jsonify({'error': 'Invalid NVIDIA API key'}), 400
    
    if brave_key:
        test = BraveSearch(brave_key)
        if not test.search("test", 1):
            return jsonify({'error': 'Invalid Brave API key'}), 400
    
    if brave_key:
        user.brave_api_key = encrypt_key(brave_key)
    # if gemini_key:
        # user.gemini_api_key = encrypt_key(gemini_key)
    if nvidia_key:
        user.nvidia_api_key = encrypt_key(nvidia_key)
    
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/analyze', methods=['POST'])
@jwt_required()
def analyze():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    # check API keys
    brave_key = decrypt_key(user.brave_api_key)
    nvidia_key = decrypt_key(user.nvidia_api_key)
    
    if not brave_key or not nvidia_key:
        return jsonify({'error': 'API keys not configured'}), 400
    
    # Rate limiting
    allowed, ttl = check_rate_limit(user_id, user.subscription_tier)
    if not allowed:
        return jsonify({
            'error': 'Rate limit exceeded',
            'retry_after': ttl,
            'upgrade_url': '/api/stripe/checkout'
        }), 429
    
    data = request.get_json()
    file_id = data.get('file_id')  # New: optional file reference
    chat_text = data.get('chat_log', '')
    recipient = data.get('recipient', 'Partner')
    location = data.get('location', 'Lagos, Nigeria')
    budget = data.get('budget', '100')
    currency = data.get('currency', 'USD')
    max_results = data.get('max_results', 4)

    # If file_id provided, fetch content from R2
    if file_id:
        chat_file = ChatFile.query.get(file_id)
        if not chat_file or chat_file.user_id != user_id:
            return jsonify({'error': 'File not found'}), 404
        
        # Get content from R2
        r2_key = chat_file.r2_key
        if R2_PUBLIC_URL and chat_file.r2_url.startswith(R2_PUBLIC_URL):
            r2_key = chat_file.r2_url.replace(f"{R2_PUBLIC_URL}/", "")
        
        content = get_file_content(r2_key)
        if content:
            chat_text = content
        else:
            return jsonify({'error': 'Failed to load file content'}), 500
    
    if not chat_text:
        return jsonify({'error': 'No chat log provided'}), 400
    
    # Phase 1: Analyze
    # analyzer = PainPointAnalyzer(gemini_key)
    analyzer = PainPointAnalyzer(nvidia_key)
    pains = analyzer.analyze(chat_text, recipient)
    
    if not pains:
        return jsonify({'error': 'No pain points detected'}), 400
    
    # Phase 2: Shopping
    # shopper = ShoppingAgent(gemini_key, brave_key)
    shopper = ShoppingAgent(nvidia_key, brave_key)
    gifts = []
    total_searches = 0
    
    for pain in pains[:5]:
        if len(gifts) >= 3:
            break
        
        ideas = shopper.brainstorm(pain.get('pain_point', ''), location)
        
        for strategy, item in ideas.items():
            if not isinstance(item, str):
                continue
            
            query = f"buy {item} online {location} price"
            results = shopper.search.search(query, max_results=max_results)
            total_searches += 1
            
            if results:
                rec = shopper.vet(item, results, budget, currency, location)
                if rec:
                    rec['strategy'] = strategy
                    rec['pain_point'] = pain.get('pain_point', '')
                    rec['pain_score'] = pain.get('score', 0)
                    gifts.append(rec)
                    break
    
    # Save analysis
    analysis = Analysis(
        user_id=user.id,
        recipient_name=recipient,
        location=location,
        budget=budget,
        currency=currency,
        chat_log=chat_text[:2000],
        pain_points=json.dumps(pains),
        recommendations=json.dumps(gifts),
        search_count=total_searches
    )
    db.session.add(analysis)
    db.session.flush()  # Get analysis.id

    # Update file with analysis reference
    if file_id:
        chat_file.analysis_id = analysis.id
        chat_file.is_processed = True
    
    # Update usage
    user.monthly_searches += total_searches
    user.total_analyses += 1
    user.last_active = datetime.utcnow()
    db.session.commit()
    
    return jsonify({
        'pains': pains,
        'gifts': gifts,
        'search_count': total_searches,
        'saved_calls': (len(pains) * 3) - total_searches,
        'analysis_id': analysis.id
    })

@app.route('/api/upload', methods=['POST'])
@jwt_required()
def upload_file():
    """Handle WhatsApp chat file upload to R2"""
    user_id = get_jwt_identity()
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400
    
    # Validate file type
    allowed_extensions = {'.txt', '.zip', '.csv'}
    file_ext = os.path.splitext(file.filename)[1].lower()
    if file_ext not in allowed_extensions:
        return jsonify({'error': f'Invalid file type. Allowed: {allowed_extensions}'}), 400
    
    # Validate file size (max 10MB)
    file_data = file.read()
    if len(file_data) > 10 * 1024 * 1024:
        return jsonify({'error': 'File too large (max 10MB)'}), 400
    
    # Upload to R2
    success, file_url, error = upload_chat_file(
        file_data=file_data,
        user_id=user_id,
        original_filename=file.filename
    )
    
    if not success:
        return jsonify({'error': f'Upload failed: {error}'}), 500
    
    # Save reference to database
    chat_file = ChatFile(
        user_id=user_id,
        original_filename=file.filename,
        r2_key=file_url.split('/')[-2] + '/' + file_url.split('/')[-1] if R2_PUBLIC_URL else file_url,
        r2_url=file_url,
        file_size=len(file_data),
        mime_type='text/plain'
    )
    db.session.add(chat_file)
    db.session.commit()
    
    # Extract text content for immediate analysis
    try:
        if file_ext == '.zip':
            import zipfile
            import io
            with zipfile.ZipFile(io.BytesIO(file_data)) as z:
                # Find _chat.txt inside zip
                chat_txt = [f for f in z.namelist() if '_chat.txt' in f]
                if chat_txt:
                    content = z.read(chat_txt[0]).decode('utf-8', errors='ignore')
                else:
                    content = z.read(z.namelist()[0]).decode('utf-8', errors='ignore')
        else:
            content = file_data.decode('utf-8', errors='ignore')
    except Exception as e:
        content = None
    
    return jsonify({
        'success': True,
        'file_id': chat_file.id,
        'file_url': file_url,
        'file_size': len(file_data),
        'content_preview': content[:1000] if content else None,
        'full_content': content if len(content) < 50000 else None  # Return full if under 50KB
    })

@app.route('/api/files', methods=['GET'])
@jwt_required()
def list_files():
    """List user's uploaded files"""
    user_id = get_jwt_identity()
    files = ChatFile.query.filter_by(user_id=user_id).order_by(ChatFile.created_at.desc()).all()
    
    return jsonify([{
        'id': f.id,
        'original_filename': f.original_filename,
        'file_size': f.file_size,
        'r2_url': f.r2_url,
        'is_processed': f.is_processed,
        'created_at': f.created_at.isoformat(),
        'analysis_id': f.analysis_id
    } for f in files])

@app.route('/api/files/<int:file_id>', methods=['DELETE'])
@jwt_required()
def delete_file(file_id):
    """Delete uploaded file"""
    user_id = get_jwt_identity()
    file = ChatFile.query.get_or_404(file_id)
    
    if file.user_id != user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Delete from R2
    if file.r2_key:
        delete_chat_file(file.r2_key)
    
    # Delete from database
    db.session.delete(file)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/files/<int:file_id>/content', methods=['GET'])
@jwt_required()
def get_file_content_route(file_id):
    """Get file content from R2"""
    user_id = get_jwt_identity()
    file = ChatFile.query.get_or_404(file_id)
    
    if file.user_id != user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Extract key from URL
    if R2_PUBLIC_URL and file.r2_url.startswith(R2_PUBLIC_URL):
        r2_key = file.r2_url.replace(f"{R2_PUBLIC_URL}/", "")
    else:
        r2_key = file.r2_key
    
    content = get_file_content(r2_key)
    
    if content is None:
        return jsonify({'error': 'Failed to retrieve file'}), 500
    
    return jsonify({
        'content': content,
        'filename': file.original_filename
    })

@app.route('/api/history', methods=['GET'])
@jwt_required()
def get_history():
    user_id = get_jwt_identity()
    analyses = Analysis.query.filter_by(user_id=user_id).order_by(Analysis.created_at.desc()).all()
    
    return jsonify([{
        'id': a.id,
        'recipient': a.recipient_name,
        'location': a.location,
        'budget': a.budget,
        'currency': a.currency,
        'gift_count': len(json.loads(a.recommendations)) if a.recommendations else 0,
        'created_at': a.created_at.isoformat()
    } for a in analyses])

@app.route('/api/history/<int:analysis_id>', methods=['GET'])
@jwt_required()
def get_analysis(analysis_id):
    user_id = get_jwt_identity()
    analysis = Analysis.query.get_or_404(analysis_id)
    
    if analysis.user_id != user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    return jsonify({
        'id': analysis.id,
        'recipient': analysis.recipient_name,
        'location': analysis.location,
        'budget': analysis.budget,
        'currency': analysis.currency,
        'pains': json.loads(analysis.pain_points) if analysis.pain_points else [],
        'gifts': json.loads(analysis.recommendations) if analysis.recommendations else [],
        'search_count': analysis.search_count,
        'created_at': analysis.created_at.isoformat()
    })

# Stripe Routes
@app.route('/api/stripe/checkout', methods=['POST'])
@jwt_required()
def create_checkout():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    tier = request.json.get('tier', 'pro')
    
    prices = {
        'pro': os.environ.get('STRIPE_PRICE_PRO', 'price_123'),
        'enterprise': os.environ.get('STRIPE_PRICE_ENTERPRISE', 'price_456')
    }
    
    # Create customer if needed
    if not user.stripe_customer_id:
        customer = stripe.Customer.create(email=user.email, name=user.name)
        user.stripe_customer_id = customer.id
        db.session.commit()
    
    session = stripe.checkout.Session.create(
        customer=user.stripe_customer_id,
        payment_method_types=['card'],
        line_items=[{
            'price': prices.get(tier, prices['pro']),
            'quantity': 1,
        }],
        mode='subscription',
        success_url=os.environ.get('FRONTEND_URL') + '/settings?success=true',
        cancel_url=os.environ.get('FRONTEND_URL') + '/settings?canceled=true',
    )
    
    return jsonify({'url': session.url})

@app.route('/api/stripe/portal', methods=['POST'])
@jwt_required()
def customer_portal():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user.stripe_customer_id:
        return jsonify({'error': 'No subscription found'}), 400
    
    portal = stripe.billing_portal.Session.create(
        customer=user.stripe_customer_id,
        return_url=os.environ.get('FRONTEND_URL') + '/settings'
    )
    
    return jsonify({'url': portal.url})

@app.route('/api/stripe/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature')
    
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except ValueError:
        return jsonify({'error': 'Invalid payload'}), 400
    except stripe.error.SignatureVerificationError:
        return jsonify({'error': 'Invalid signature'}), 400
    
    # Handle events
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        customer_id = session['customer']
        
        user = User.query.filter_by(stripe_customer_id=customer_id).first()
        if user:
            user.subscription_status = 'active'
            user.subscription_tier = 'pro'  # Determine from session
            user.subscription_end_date = datetime.utcnow() + timedelta(days=30)
            db.session.commit()
    
    elif event['type'] == 'customer.subscription.deleted':
        subscription = event['data']['object']
        customer_id = subscription['customer']
        
        user = User.query.filter_by(stripe_customer_id=customer_id).first()
        if user:
            user.subscription_status = 'canceled'
            user.subscription_tier = 'free'
            db.session.commit()
    
    return jsonify({'status': 'success'})

@app.route('/api/paystack/initialize', methods=['POST'])
@jwt_required()
def paystack_initialize():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    tier = request.json.get('tier', 'pro')
    
    plans = {
        'pro': os.environ.get('PAYSTACK_PLAN_PRO'),
        'enterprise': os.environ.get('PAYSTACK_PLAN_ENTERPRISE')
    }
    plan_code = plans.get(tier, plans['pro'])
    
    amounts = {'pro': 500000, 'enterprise': 1500000}  # In kobo (₦5,000 / ₦15,000)
    amount_kobo = amounts.get(tier, 500000)
    
    if not user.paystack_customer_code:
        customer_code = create_paystack_customer(
            user.email,
            user.name.split()[0] if user.name else 'User',
            user.name.split()[-1] if user.name and len(user.name.split()) > 1 else ''
        )
        user.paystack_customer_code = customer_code
        db.session.commit()
    
    auth_url = initialize_transaction(user.email, amount_kobo, plan_code=plan_code)
    return jsonify({'authorization_url': auth_url})

@app.route('/api/paystack/webhook', methods=['POST'])
def paystack_webhook():
    signature = request.headers.get('x-paystack-signature')
    expected = hmac.new(
        PAYSTACK_SECRET_KEY.encode(),
        request.get_data(),
        hashlib.sha512
    ).hexdigest()
    
    if signature != expected:
        return jsonify({'error': 'Invalid signature'}), 400
    
    event = request.json
    event_type = event.get('event')
    data = event.get('data', {})
    
    if event_type == 'charge.success':
        email = data.get('customer', {}).get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            user.subscription_status = 'active'
            user.subscription_tier = 'pro'
            user.paystack_subscription_code = data.get('subscription', {}).get('subscription_code')
            db.session.commit()
    
    elif event_type == 'subscription.disable':
        subscription_code = data.get('subscription_code')
        user = User.query.filter_by(paystack_subscription_code=subscription_code).first()
        if user:
            user.subscription_status = 'canceled'
            user.subscription_tier = 'free'
            db.session.commit()
    
    return jsonify({'status': 'success'})

@app.route('/api/user/subscription', methods=['GET'])
@jwt_required()
def get_subscription():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    return jsonify({
        'tier': user.subscription_tier,
        'status': user.subscription_status,
        'searches_this_month': user.monthly_searches,
        'search_limit': 50 if user.subscription_tier == 'free' else (500 if user.subscription_tier == 'pro' else 5000),
        'total_analyses': user.total_analyses
    })

@app.before_first_request
def create_tables():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
