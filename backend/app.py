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
from concurrent.futures import ThreadPoolExecutor, as_completed
import stripe
from authlib.integrations.flask_client import OAuth
import redis
import boto3

app = Flask(__name__)
# app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
# app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///gifts.db')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-fallback-change-in-prod')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///gifts.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,       # Check connection liveness before each use
    'pool_recycle': 300,         # Recycle connections every 5 min (prevents stale SSL)
    'pool_size': 5,
    'max_overflow': 10,
}
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'jwt-fallback-change-in-prod')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=7)

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
# CORS(app, origins=[os.environ.get('FRONTEND_URL', 'http://localhost:5173')], supports_credentials=True)
frontend_url = os.environ.get('FRONTEND_URL', '')
cors_origins = [o for o in [frontend_url, 'https://gift-recommender-seven.vercel.app', 'http://localhost:5173'] if o]
CORS(app, origins=cors_origins, supports_credentials=True)

# Redis for rate limiting and caching
redis_url = os.environ.get('REDIS_URL')
redis_client = None
if redis_url and redis_url.strip():
    try:
        redis_client = redis.from_url(redis_url)
    except:
        redis_client = None

# Encryption
import base64
_enc_key_raw = os.environ.get('ENCRYPTION_KEY')
if not _enc_key_raw:
    _enc_key = Fernet.generate_key()
else:
    # Try using the value directly as a Fernet key
    try:
        _test = _enc_key_raw.encode() if isinstance(_enc_key_raw, str) else _enc_key_raw
        Fernet(_test)  # validate
        _enc_key = _test
    except (ValueError, Exception):
        # Derive a valid 32-byte Fernet key from arbitrary input via SHA256
        _derived = hashlib.sha256(_enc_key_raw.encode()).digest()
        _enc_key = base64.urlsafe_b64encode(_derived)
        print(f"⚠️ ENCRYPTION_KEY was not a valid Fernet key — derived one via SHA256")
cipher_suite = Fernet(_enc_key)

# Stripe setup
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET')

# App-level API keys (set by developer, not per-user)
BRAVE_API_KEY = os.environ.get('BRAVE_API_KEY')
NVIDIA_API_KEY = os.environ.get('NVIDIA_API_KEY')

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

# Encryption helpers defined below (after models) - encrypt_key() / decrypt_key()

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
        
    def generate(self, prompt, max_retries=2):
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
        for attempt in range(max_retries):
            try:
                response = requests.post(self.invoke_url, headers=headers, json=payload, timeout=120)
                response.raise_for_status()
                data = response.json()
                if 'choices' in data and len(data['choices']) > 0:
                    return data['choices'][0]['message']['content']
                return "{}"
            except requests.exceptions.Timeout:
                print(f"⏳ Kimi API timeout (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    time.sleep(5)  # backoff before retry
                    continue
                print("❌ Kimi API timeout after all retries")
                return "__TIMEOUT__"
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
IMPORTANT: Group similar complaints together. Return EXACTLY 3 consolidated pain point categories.
For example, merge "back pain", "neck stiffness", and "posture problems" into one "Posture & Body Pain" category.
Pick the most representative quote as trigger_text and average the severity for the score.
Return JSON array with EXACTLY 3 items, each with fields: pain_point (string), score (1-10), category (Physical/Emotional/Practical), trigger_text (exact quote from chat), context (brief summary of all related complaints in this group).
Chat: {chat_text[:4000]}"""
        resp = self.kimi.generate(prompt)
        if resp == "__TIMEOUT__":
            return "__TIMEOUT__"
        try:
            match = re.search(r'\[.*\]', resp.replace("\n", " "), re.DOTALL)
            results = json.loads(match.group(0)) if match else []
            return results[:3]  # Hard cap at 3
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
        prompt = f"""Someone is experiencing this specific problem: "{pain_point}".
Think carefully about what would DIRECTLY solve or significantly relieve this exact problem.
Suggest 3 specific product types that would be the most beneficial, useful, and satisfying gift to help with this exact issue:
- practical: An everyday functional product that directly addresses this problem
- splurge: A premium/luxury version of a product that solves this problem
- thoughtful: A creative or caring gift that shows you understand their struggle
Each suggestion should be 2-4 words describing a specific product type (not a brand).
The product MUST directly help with "{pain_point}" — do NOT suggest unrelated products.
Return JSON: {{"practical": "...", "splurge": "...", "thoughtful": "..."}}"""
        resp = self.kimi.generate(prompt)
        try:
            match = re.search(r'\{.*\}', resp.replace("\n", " "), re.DOTALL)
            return json.loads(match.group(0)) if match else {"practical": pain_point + " solution"}
        except:
            return {"practical": pain_point + " solution"}
    
    def vet(self, item, results, budget, currency, location, pain_point):
        prompt = f"""The recipient is struggling with: "{pain_point}"
We searched for "{item}" to help them. Here are {len(results[:5])} search results: {json.dumps(results[:5])}

RULES:
1. PREFER results whose URL ("href") leads to a specific product page (e.g. jiji.ng/lagos/furniture/abcde.html, amazon.com/dp/B09XYZ, jumia.com.ng/product-name-12345.html). Avoid search result pages or category pages if possible.
2. "price_guess" should be a real price from the result title or description ("body"). Look for price patterns like ₦XX,XXX or $XX. If no exact price is visible, give your best estimate based on the description.
3. "url" MUST be copied exactly from the "href" field of a result. Do NOT invent URLs.

Return JSON:
- "product": the product name from the search result
- "price_guess": price as a number string (no currency symbol)
- "url": the exact "href" from the chosen result
- "reason": A warm 1-2 sentence description of how this gift helps solve their "{pain_point}". Do NOT mention the website, shipping, or pricing. Write as a thoughtful friend.
- "technical_reason": Technical analysis for developer logs only.

Return {{}} if nothing is under {budget} {currency}."""
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
        
        access_token = create_access_token(identity=str(user.id))
        
        return jsonify({
            'access_token': access_token,
            'user': {
                'id': user.id,
                'email': user.email,
                'name': user.name,
                'avatar': user.avatar,
                'subscription_tier': user.subscription_tier,
                'has_api_keys': True  # API keys are now app-level, always available
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 401

@app.route('/api/user/keys', methods=['GET', 'POST'])
@jwt_required()
def user_keys():
    # API keys are now managed at the app level by the developer
    # This route is kept as a no-op for backward compatibility
    return jsonify({
        'has_keys': True,
        'message': 'API keys are managed by the application'
    })

@app.route('/api/analyze', methods=['POST'])
@jwt_required()
def analyze():
  try:
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)

    # Use app-level API keys (set by developer)
    brave_key = BRAVE_API_KEY
    nvidia_key = NVIDIA_API_KEY
    
    if not brave_key or not nvidia_key:
        return jsonify({'error': 'Service temporarily unavailable. Please contact support.'}), 503
    
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
    
    if pains == "__TIMEOUT__":
        return jsonify({'error': 'AI service timed out. The Kimi API may be experiencing high load — please try again in a minute.'}), 504
    
    if not pains:
        return jsonify({'error': 'No pain points detected — try pasting a longer or more detailed chat log.'}), 400
    
    # Phase 2: Shopping — sort pain points by score, pick the highest
    shopper = ShoppingAgent(nvidia_key, brave_key)
    gifts = []
    total_searches = 0
    
    # Sort pain points by score (highest first) and pick the top one
    sorted_pains = sorted(pains, key=lambda p: p.get('score', 0), reverse=True)
    top_pain = sorted_pains[0] if sorted_pains else None
    
    if top_pain:
        pain_text = top_pain.get('pain_point', '')
        pain_score = top_pain.get('score', 0)
        
        # Brainstorm 3 gift ideas (practical, splurge, thoughtful) for the top pain point
        ideas = shopper.brainstorm(pain_text, location)
        
        # Search and vet each strategy IN PARALLEL for speed
        def search_and_vet(strategy, item):
            # Search for specific product listings with price in the location
            query = f"{item} price {location}"
            results = shopper.search.search(query, max_results=max(max_results, 6))
            # Fallback with broader query if no results
            if not results:
                results = shopper.search.search(f"buy {item} online {location}", max_results=6)
            if results:
                rec = shopper.vet(item, results, budget, currency, location, pain_text)
                if rec:
                    rec['strategy'] = strategy
                    rec['pain_point'] = pain_text
                    rec['pain_score'] = pain_score
                    return rec
            return None
        
        tasks = []
        with ThreadPoolExecutor(max_workers=3) as executor:
            for strategy in ['practical', 'splurge', 'thoughtful']:
                item = ideas.get(strategy)
                if item and isinstance(item, str):
                    tasks.append(executor.submit(search_and_vet, strategy, item))
                    total_searches += 1
            
            for future in as_completed(tasks):
                try:
                    rec = future.result()
                    if rec:
                        gifts.append(rec)
                except Exception as e:
                    print(f"⚠️ Search/vet error: {e}")
    
    # Log technical details for developer (backend only)
    saved_calls = (len(pains) * 3) - total_searches
    print(f"📊 Analysis stats — Pain points: {len(pains)}, Searches: {total_searches}, API calls saved: {saved_calls}")
    for i, gift in enumerate(gifts):
        tech_reason = gift.get('technical_reason', 'N/A')
        print(f"🎁 Gift {i+1} [{gift.get('product', '?')}] technical_reason: {tech_reason}")
    
    # Strip technical_reason from gifts before saving/returning
    gifts_for_frontend = []
    for gift in gifts:
        clean_gift = {k: v for k, v in gift.items() if k != 'technical_reason'}
        gifts_for_frontend.append(clean_gift)
    
    # Save analysis (with technical reasons stripped)
    analysis = Analysis(
        user_id=user.id,
        recipient_name=recipient,
        location=location,
        budget=budget,
        currency=currency,
        chat_log=chat_text[:2000],
        pain_points=json.dumps(pains),
        recommendations=json.dumps(gifts_for_frontend),
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
        'gifts': gifts_for_frontend,
        'search_count': total_searches,
        'analysis_id': analysis.id
    })
  except Exception as e:
    print(f"❌ Analyze error: {e}")
    import traceback
    traceback.print_exc()
    return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

@app.route('/api/search-similar', methods=['POST'])
@jwt_required()
def search_similar():
    """Find similar products to a given gift — powers the 'More like this' button.
    Uses the same ShoppingAgent search + vet pipeline as the initial gift search."""
    try:
        user_id = int(get_jwt_identity())
        user = User.query.get(user_id)
        
        brave_key = BRAVE_API_KEY
        nvidia_key = NVIDIA_API_KEY
        if not brave_key or not nvidia_key:
            return jsonify({'error': 'Service temporarily unavailable.'}), 503
        
        data = request.get_json()
        product = data.get('product', '')
        pain_point = data.get('pain_point', '')
        budget = data.get('budget', '100')
        currency = data.get('currency', 'USD')
        location = data.get('location', 'Lagos, Nigeria')
        
        if not product:
            return jsonify({'error': 'No product specified'}), 400
        
        # Use the same ShoppingAgent as the main search
        shopper = ShoppingAgent(nvidia_key, brave_key)
        
        # Generate 3 alternative product ideas based on the original product + pain point
        kimi = KimiClient(nvidia_key)
        prompt = f"""Someone struggling with "{pain_point}" was recommended "{product}".
Suggest 3 DIFFERENT but similar product types that also directly solve "{pain_point}".
Each should be a distinct alternative (not the same product), 2-4 words each.
Return JSON: {{"alt1": "...", "alt2": "...", "alt3": "..."}}"""
        resp = kimi.generate(prompt)
        try:
            match = re.search(r'\{.*\}', resp.replace("\n", " "), re.DOTALL)
            alt_ideas = json.loads(match.group(0)) if match else {}
        except:
            alt_ideas = {"alt1": product}
        
        # Search and vet each alternative IN PARALLEL (same as main search)
        alternatives = []
        total_searches = 0
        
        def search_and_vet_alt(item):
            query = f"{item} price {location}"
            results = shopper.search.search(query, max_results=6)
            if not results:
                results = shopper.search.search(f"buy {item} online {location}", max_results=6)
            if results:
                rec = shopper.vet(item, results, budget, currency, location, pain_point)
                if rec:
                    # Strip technical_reason before returning
                    clean = {k: v for k, v in rec.items() if k != 'technical_reason'}
                    return clean
            return None
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = []
            for key, item in alt_ideas.items():
                if item and isinstance(item, str):
                    futures.append(executor.submit(search_and_vet_alt, item))
                    total_searches += 1
            
            for future in as_completed(futures):
                try:
                    rec = future.result()
                    if rec:
                        alternatives.append(rec)
                except Exception as e:
                    print(f"⚠️ Search-similar vet error: {e}")
        
        # Update search count
        user.monthly_searches += total_searches
        db.session.commit()
        
        return jsonify({'alternatives': alternatives})
    except Exception as e:
        print(f"❌ Search-similar error: {e}")
        return jsonify({'error': 'Search failed'}), 500

@app.route('/api/upload', methods=['POST'])
@jwt_required()
def upload_file():
    """Handle chat file upload — supports WhatsApp, Telegram, Snapchat, Instagram, TikTok, iMessage"""
    user_id = int(get_jwt_identity())
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400
    
    # Validate file type
    allowed_extensions = {'.txt', '.zip', '.csv', '.json', '.html'}
    file_ext = os.path.splitext(file.filename)[1].lower()
    if file_ext not in allowed_extensions:
        return jsonify({'error': f'Invalid file type. Allowed: .txt, .zip, .csv, .json, .html'}), 400
    
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
    
    # Parse chat content from various platforms
    content = parse_chat_file(file_data, file_ext, file.filename)
    
    return jsonify({
        'success': True,
        'file_id': chat_file.id,
        'file_url': file_url,
        'file_size': len(file_data),
        'content_preview': content[:1000] if content else None,
        'full_content': content if content and len(content) < 50000 else None
    })


def parse_chat_file(file_data, file_ext, filename=''):
    """Parse chat file from multiple platforms into a unified format.
    Supported: WhatsApp, Telegram, Snapchat, Instagram, TikTok, iMessage.
    Output format: [date] sender: message (one per line)"""
    try:
        # ZIP files (WhatsApp export)
        if file_ext == '.zip':
            import zipfile
            import io
            with zipfile.ZipFile(io.BytesIO(file_data)) as z:
                # WhatsApp zips contain _chat.txt
                chat_txt = [f for f in z.namelist() if '_chat.txt' in f or f.endswith('.txt')]
                if chat_txt:
                    raw = z.read(chat_txt[0]).decode('utf-8', errors='ignore')
                    return raw  # WhatsApp .txt is already in usable format
                # Could also contain .json (Telegram desktop export)
                json_files = [f for f in z.namelist() if f.endswith('.json')]
                if json_files:
                    raw = z.read(json_files[0]).decode('utf-8', errors='ignore')
                    return parse_json_chat(raw, filename)
                return z.read(z.namelist()[0]).decode('utf-8', errors='ignore')
        
        raw_text = file_data.decode('utf-8', errors='ignore')
        
        # JSON files — detect platform and parse
        if file_ext == '.json':
            return parse_json_chat(raw_text, filename)
        
        # HTML files — Telegram HTML export
        if file_ext == '.html':
            return parse_html_chat(raw_text)
        
        # CSV files — iMessage / generic CSV
        if file_ext == '.csv':
            return parse_csv_chat(raw_text)
        
        # .txt files — WhatsApp or generic text
        return raw_text
        
    except Exception as e:
        print(f"⚠️ Chat parse error: {e}")
        # Fall back to raw text
        try:
            return file_data.decode('utf-8', errors='ignore')
        except:
            return None


def parse_json_chat(raw_text, filename=''):
    """Parse JSON chat exports from Telegram, Snapchat, Instagram, TikTok"""
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError:
        return raw_text  # Not valid JSON, return as-is
    
    lines = []
    
    # --- Telegram JSON export ---
    # Structure: {"messages": [{"from": "...", "date": "...", "text": "..."}]}
    if isinstance(data, dict) and 'messages' in data:
        for msg in data['messages']:
            if msg.get('type') != 'message':
                continue
            sender = msg.get('from', msg.get('from_id', 'Unknown'))
            date = msg.get('date', '')[:10]  # YYYY-MM-DD
            text = msg.get('text', '')
            # Telegram text can be a list of objects for formatted text
            if isinstance(text, list):
                text = ''.join(
                    part if isinstance(part, str) else part.get('text', '')
                    for part in text
                )
            if text.strip():
                lines.append(f"[{date}] {sender}: {text.strip()}")
        if lines:
            return '\n'.join(lines)
    
    # --- Instagram JSON export ---
    # Structure: {"participants": [...], "messages": [{"sender_name": "...", "timestamp_ms": ..., "content": "..."}]}
    if isinstance(data, dict) and 'participants' in data and 'messages' in data:
        for msg in sorted(data['messages'], key=lambda m: m.get('timestamp_ms', 0)):
            sender = msg.get('sender_name', 'Unknown')
            # Fix Instagram's UTF-8 encoding issue
            try:
                sender = sender.encode('latin1').decode('utf-8')
            except:
                pass
            ts = msg.get('timestamp_ms', 0)
            from datetime import datetime as dt
            date = dt.fromtimestamp(ts / 1000).strftime('%m/%d/%y') if ts else ''
            content = msg.get('content', '')
            try:
                content = content.encode('latin1').decode('utf-8')
            except:
                pass
            if content.strip():
                lines.append(f"[{date}] {sender}: {content.strip()}")
        if lines:
            return '\n'.join(lines)
    
    # --- Snapchat JSON export ---
    # Structure: [{"From": "...", "Created": "...", "Content": "..."}] or {"Saved Messages": [...]}
    if isinstance(data, list):
        for msg in data:
            sender = msg.get('From', msg.get('sender', msg.get('from', 'Unknown')))
            date = msg.get('Created', msg.get('date', msg.get('timestamp', '')))[:10]
            content = msg.get('Content', msg.get('content', msg.get('text', msg.get('message', ''))))
            if content and str(content).strip():
                lines.append(f"[{date}] {sender}: {str(content).strip()}")
        if lines:
            return '\n'.join(lines)
    
    if isinstance(data, dict) and 'Saved Messages' in data:
        for msg in data['Saved Messages']:
            sender = msg.get('From', 'Unknown')
            date = msg.get('Created', '')[:10]
            content = msg.get('Content', '')
            if content.strip():
                lines.append(f"[{date}] {sender}: {content.strip()}")
        if lines:
            return '\n'.join(lines)
    
    # --- TikTok JSON export ---
    # Structure: {"ChatHistory": {"ChatHistory": [{"From": "...", "Date": "...", "Content": "..."}]}}
    if isinstance(data, dict) and 'ChatHistory' in data:
        chat_hist = data['ChatHistory']
        if isinstance(chat_hist, dict) and 'ChatHistory' in chat_hist:
            chat_hist = chat_hist['ChatHistory']
        if isinstance(chat_hist, list):
            for msg in chat_hist:
                sender = msg.get('From', 'Unknown')
                date = msg.get('Date', '')[:10]
                content = msg.get('Content', '')
                if content.strip():
                    lines.append(f"[{date}] {sender}: {content.strip()}")
            if lines:
                return '\n'.join(lines)
    
    # --- Generic JSON fallback ---
    # Try to find any array of message-like objects
    for key, val in (data.items() if isinstance(data, dict) else []):
        if isinstance(val, list) and len(val) > 0 and isinstance(val[0], dict):
            for msg in val:
                sender = (msg.get('from') or msg.get('sender') or msg.get('From') or 
                         msg.get('sender_name') or msg.get('author') or 'Unknown')
                content = (msg.get('text') or msg.get('content') or msg.get('Content') or 
                          msg.get('message') or msg.get('body') or '')
                if str(content).strip():
                    lines.append(f"{sender}: {str(content).strip()}")
            if lines:
                return '\n'.join(lines)
    
    return raw_text


def parse_html_chat(raw_text):
    """Parse HTML chat exports (primarily Telegram HTML export)"""
    from html.parser import HTMLParser
    
    class TelegramHTMLParser(HTMLParser):
        def __init__(self):
            super().__init__()
            self.messages = []
            self.current_sender = ''
            self.current_text = ''
            self.current_date = ''
            self.in_sender = False
            self.in_text = False
            self.in_date = False
            
        def handle_starttag(self, tag, attrs):
            attrs_dict = dict(attrs)
            cls = attrs_dict.get('class', '')
            if 'from_name' in cls:
                self.in_sender = True
                self.current_sender = ''
            elif 'text' in cls and tag == 'div':
                self.in_text = True
                self.current_text = ''
            elif 'date' in cls:
                self.in_date = True
                # Telegram puts date in title attribute
                self.current_date = attrs_dict.get('title', '')[:10]
                
        def handle_endtag(self, tag):
            if self.in_sender:
                self.in_sender = False
            if self.in_text and tag == 'div':
                self.in_text = False
                if self.current_text.strip():
                    self.messages.append(
                        f"[{self.current_date}] {self.current_sender}: {self.current_text.strip()}"
                    )
            if self.in_date:
                self.in_date = False
                
        def handle_data(self, data):
            if self.in_sender:
                self.current_sender += data.strip()
            elif self.in_text:
                self.current_text += data
    
    try:
        parser = TelegramHTMLParser()
        parser.feed(raw_text)
        if parser.messages:
            return '\n'.join(parser.messages)
    except:
        pass
    
    # Fallback: strip all HTML tags and return plain text
    import re as re_module
    clean = re_module.sub(r'<[^>]+>', ' ', raw_text)
    clean = re_module.sub(r'\s+', ' ', clean).strip()
    return clean


def parse_csv_chat(raw_text):
    """Parse CSV chat exports (iMessage/generic CSV)"""
    import csv
    import io
    
    lines = []
    try:
        reader = csv.DictReader(io.StringIO(raw_text))
        headers = [h.lower() for h in (reader.fieldnames or [])]
        
        # Find the right column names
        sender_col = next((h for h in reader.fieldnames or [] 
                          if h.lower() in ['sender', 'from', 'name', 'handle', 'contact', 'phone']), None)
        text_col = next((h for h in reader.fieldnames or [] 
                        if h.lower() in ['text', 'message', 'body', 'content', 'imessage']), None)
        date_col = next((h for h in reader.fieldnames or [] 
                        if h.lower() in ['date', 'timestamp', 'time', 'datetime', 'sent']), None)
        
        if text_col:
            for row in reader:
                sender = row.get(sender_col, 'Unknown') if sender_col else 'Unknown'
                text = row.get(text_col, '')
                date = row.get(date_col, '') if date_col else ''
                if date:
                    date = date[:10]
                if text and text.strip():
                    lines.append(f"[{date}] {sender}: {text.strip()}")
        
        if lines:
            return '\n'.join(lines)
    except Exception as e:
        print(f"⚠️ CSV parse error: {e}")
    
    return raw_text

@app.route('/api/files', methods=['GET'])
@jwt_required()
def list_files():
    """List user's uploaded files"""
    user_id = int(get_jwt_identity())
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
    user_id = int(get_jwt_identity())
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
    user_id = int(get_jwt_identity())
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
    user_id = int(get_jwt_identity())
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
    user_id = int(get_jwt_identity())
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
    user_id = int(get_jwt_identity())
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
    user_id = int(get_jwt_identity())
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
    user_id = int(get_jwt_identity())
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
        PAYSTACK_SECRET.encode(),
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
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)
    
    return jsonify({
        'tier': user.subscription_tier,
        'status': user.subscription_status,
        'searches_this_month': user.monthly_searches,
        'search_limit': 50 if user.subscription_tier == 'free' else (500 if user.subscription_tier == 'pro' else 5000),
        'total_analyses': user.total_analyses
    })

# Create tables on startup (compatible with Flask 2.3+)
with app.app_context():
    try:
        db.create_all()
    except Exception as e:
        print(f"Warning: Could not create tables: {e}")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
