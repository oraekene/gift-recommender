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
import stripe
from authlib.integrations.flask_client import OAuth
import redis

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///gifts.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-change-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=7)

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
CORS(app, origins=[os.environ.get('FRONTEND_URL', 'http://localhost:5173')], supports_credentials=True)

# Redis for rate limiting and caching
redis_url = os.environ.get('REDIS_URL')
redis_client = redis.from_url(redis_url) if redis_url else None

# Stripe setup
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET')

# Google OAuth setup
oauth = OAuth(app)
oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# Encryption for API keys
from cryptography.fernet import Fernet
cipher_suite = Fernet(os.environ.get('ENCRYPTION_KEY', Fernet.generate_key()))

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    google_id = db.Column(db.String(255), unique=True)
    name = db.Column(db.String(255))
    avatar = db.Column(db.String(500))
    
    # API Keys (encrypted)
    brave_api_key = db.Column(db.Text)
    gemini_api_key = db.Column(db.Text)
    
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
    if not redis_client:
        return True, 0
    
    key = f"rate_limit:{user_id}"
    current = redis_client.get(key)
    
    limits = {'free': 50, 'pro': 500, 'enterprise': 5000}
    limit = limits.get(tier, 50)
    
    if current and int(current) >= limit:
        ttl = redis_client.ttl(key)
        return False, ttl
    
    pipe = redis_client.pipeline()
    pipe.incr(key)
    pipe.expire(key, 86400)  # 24 hours
    pipe.execute()
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

class GeminiClient:
    def __init__(self, api_key):
        self.api_key = api_key
        self.url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
        
    def generate(self, prompt):
        time.sleep(0.5)  # Rate limiting
        data = {
            "contents": [{"parts": [{"text": prompt}]}],
            "safetySettings": [{"category": c, "threshold": "BLOCK_NONE"} 
                              for c in ["HARM_CATEGORY_HARASSMENT", "HARM_CATEGORY_HATE_SPEECH",
                                       "HARM_CATEGORY_SEXUALLY_EXPLICIT", "HARM_CATEGORY_DANGEROUS_CONTENT"]]
        }
        try:
            response = requests.post(self.url, headers={'Content-Type': 'application/json'}, 
                                   json=data, timeout=30)
            if response.status_code == 200 and 'candidates' in response.json():
                return response.json()['candidates'][0]['content']['parts'][0]['text']
            return "{}"
        except Exception as e:
            print(f"Gemini error: {e}")
            return "{}"

class PainPointAnalyzer:
    def __init__(self, gemini_key):
        self.gemini = GeminiClient(gemini_key)
        
    def analyze(self, chat_text, recipient):
        prompt = f"""Analyze this chat for pain points experienced by {recipient}.
Return JSON array with fields: pain_point (string), score (1-10), category (Physical/Emotional/Practical), trigger_text (exact quote), context (brief).
Chat: {chat_text[:4000]}"""
        resp = self.gemini.generate(prompt)
        try:
            match = re.search(r'\[.*\]', resp.replace("\n", " "), re.DOTALL)
            return json.loads(match.group(0)) if match else []
        except Exception as e:
            print(f"Parse error: {e}")
            return []

class ShoppingAgent:
    def __init__(self, gemini_key, brave_key):
        self.gemini = GeminiClient(gemini_key)
        self.search = BraveSearch(brave_key)
        
    def brainstorm(self, pain_point, location):
        prompt = f"""Pain: "{pain_point}". Suggest 3 broad product categories (2-3 words each): practical, splurge, thoughtful.
Return JSON: {{"practical": "...", "splurge": "...", "thoughtful": "..."}}"""
        resp = self.gemini.generate(prompt)
        try:
            match = re.search(r'\{.*\}', resp.replace("\n", " "), re.DOTALL)
            return json.loads(match.group(0)) if match else {"practical": pain_point + " solution"}
        except:
            return {"practical": pain_point + " solution"}
    
    def vet(self, item, results, budget, currency, location):
        prompt = f"""Select best product under {budget} {currency} in {location} from these {len(results)} results: {json.dumps(results[:3])}.
Return JSON: {{"product": "Name", "price_guess": "50", "url": "link", "reason": "Why fits"}} or {{}} if over budget."""
        resp = self.gemini.generate(prompt)
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
                'has_api_keys': bool(user.brave_api_key and user.gemini_api_key)
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
        gemini_masked = '••••' + decrypt_key(user.gemini_api_key)[-4:] if user.gemini_api_key else None
        
        return jsonify({
            'brave_api_key': brave_masked,
            'gemini_api_key': gemini_masked,
            'has_keys': bool(user.brave_api_key and user.gemini_api_key)
        })
    
    # POST - update keys
    data = request.get_json()
    brave_key = data.get('brave_api_key', '').strip()
    gemini_key = data.get('gemini_api_key', '').strip()
    
    # Validate keys
    if brave_key:
        test = BraveSearch(brave_key)
        if not test.search("test", 1):
            return jsonify({'error': 'Invalid Brave API key'}), 400
    
    if brave_key:
        user.brave_api_key = encrypt_key(brave_key)
    if gemini_key:
        user.gemini_api_key = encrypt_key(gemini_key)
    
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/analyze', methods=['POST'])
@jwt_required()
def analyze():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    # Check API keys
    brave_key = decrypt_key(user.brave_api_key)
    gemini_key = decrypt_key(user.gemini_api_key)
    
    if not brave_key or not gemini_key:
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
    chat_text = data.get('chat_log', '')
    recipient = data.get('recipient', 'Partner')
    location = data.get('location', 'Lagos, Nigeria')
    budget = data.get('budget', '100')
    currency = data.get('currency', 'USD')
    max_results = data.get('max_results', 4)
    
    if not chat_text:
        return jsonify({'error': 'No chat log provided'}), 400
    
    # Phase 1: Analyze
    analyzer = PainPointAnalyzer(gemini_key)
    pains = analyzer.analyze(chat_text, recipient)
    
    if not pains:
        return jsonify({'error': 'No pain points detected'}), 400
    
    # Phase 2: Shopping
    shopper = ShoppingAgent(gemini_key, brave_key)
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
