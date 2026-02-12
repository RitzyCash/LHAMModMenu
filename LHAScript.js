import os
import json
import base64
import hashlib
import sqlite3
import io
import ssl
import secrets
import time
import threading
from flask import Flask, request, jsonify, render_template_string, send_file, redirect, make_response
from cryptography.x509.oid import NameOID
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import datetime
import cv2
import numpy as np

app = Flask(__name__)

# --- CONFIGURATION ---
CONFIG_FILE = 'config.json'
CERT_FILE = 'cert.pem'
KEY_FILE = 'key.pem'
LOG_FILE = 'vault_audit.log'
BG_DIR = 'backgrounds' # New directory for multiple BGs
SESSION_TIMEOUT = 3600  # 1 hour (Hard limit)
INITIAL_LOCKOUT = 300   
MAX_FAILED_ATTEMPTS = 3

# --- SERVER STATE ---
sessions = {}
brute_force_tracker = {}

# --- THUMBNAIL GENERATION STATE ---
thumbnail_status = {
    "is_running": False,
    "current": "",
    "count": 0,
    "total": 0,
    "errors": []
}

def log_audit(event, ip, details=""):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] IP: {ip} | EVENT: {event} | {details}\n"
    with open(LOG_FILE, "a") as f:
        f.write(log_entry)

def generate_self_signed_cert():
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"localhost")])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)).add_extension(x509.SubjectAlternativeName([x509.DNSName(u"localhost")]), critical=False).sign(key, hashes.SHA256(), default_backend())
    with open(KEY_FILE, "wb") as f:
        f.write(key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))
    with open(CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

@app.before_request
def security_checks():
    if not request.is_secure and request.headers.get('X-Forwarded-Proto', 'http') != 'https':
        return redirect(request.url.replace('http://', 'https://', 1), code=301)
    
    now = time.time()
    expired = [t for t, s in sessions.items() if now > s['expires_at']]
    for t in expired: 
        log_audit("SESSION_EXPIRED", sessions[t]['ip'], "Session reached hard timeout")
        del sessions[t]

def get_vault_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8-sig') as f:
                return json.load(f)
        except: pass
    return None

def derive_key_python(password, salt_b64):
    salt = base64.b64decode(salt_b64 + "==")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000, backend=default_backend())
    return kdf.derive(password.encode('utf-8'))

def verify_vault_password(password, config):
    try:
        derived_key = derive_key_python(password, config['salt'])
        current_verify = base64.b64encode(hashlib.sha256(derived_key).digest()).decode()
        return current_verify == config['verification_hash']
    except: return False

def get_client_ip():
    return request.remote_addr

# --- API ROUTES ---

@app.route('/')
def index():
    return render_template_string("{% raw %}" + HTML_TEMPLATE + "{% endraw %}")

@app.route('/api/status', methods=['POST'])
def get_status():
    token = request.json.get('token')
    ip = get_client_ip()
    now = time.time()
    
    valid_session = token in sessions and sessions[token]['ip'] == ip and now < sessions[token]['expires_at']
    
    expires_at = 0
    bg_ids = []
    
    config = get_vault_config()
    if config:
        vault_path = config.get("vault_path", "")
        bg_path = os.path.join(vault_path, BG_DIR)
        if os.path.exists(bg_path):
            bg_ids = [f for f in os.listdir(bg_path) if f.endswith('.enc')]

    if valid_session:
        expires_at = sessions[token]['expires_at']
    
    return jsonify({
        "authenticated": valid_session, 
        "expires_at": expires_at, 
        "backgrounds": bg_ids
    })

@app.route('/api/unlock', methods=['POST'])
def unlock_vault():
    ip = get_client_ip()
    now = time.time()
    tracker = brute_force_tracker.get(ip, {"fails": 0, "lock_until": 0, "last_wait": INITIAL_LOCKOUT})
    
    if now < tracker['lock_until']:
        return jsonify({"error": f"Locked for {int(tracker['lock_until'] - now)}s"}), 429

    pwd = request.json.get("password")
    config = get_vault_config()
    if not config: return jsonify({"error": "No config"}), 400
    
    if verify_vault_password(pwd, config):
        if ip in brute_force_tracker: del brute_force_tracker[ip]
        token = secrets.token_hex(32)
        sessions[token] = {
            "ip": ip, 
            "expires_at": now + SESSION_TIMEOUT, 
            "password": pwd
        }
        log_audit("LOGIN_SUCCESS", ip)
        return jsonify({
            "status": "success", 
            "token": token, 
            "expires_at": now + SESSION_TIMEOUT,
            "salt": config['salt'] # Return salt for client-side key derivation
        })
    else:
        tracker['fails'] += 1
        log_audit("LOGIN_FAILURE", ip, f"Fail count: {tracker['fails']}")
        tracker['lock_until'] = now + (tracker['last_wait'] if tracker['fails'] >= MAX_FAILED_ATTEMPTS else 0)
        if tracker['fails'] >= MAX_FAILED_ATTEMPTS: tracker['last_wait'] *= 2
        brute_force_tracker[ip] = tracker
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/api/videos', methods=['POST'])
def list_videos():
    token = request.json.get('token')
    if token not in sessions or sessions[token]['ip'] != get_client_ip() or time.time() > sessions[token]['expires_at']:
        return jsonify({"error": "Unauthorized"}), 401
    
    config = get_vault_config()
    db_path = os.path.join(config.get("vault_path"), "vault.db")
    videos = []
    if os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        
        # Schema Migration: Add tags column if not exists
        try:
            conn.execute("ALTER TABLE videos ADD COLUMN tags TEXT")
        except sqlite3.OperationalError:
            pass # Column already exists
            
        cursor = conn.execute("SELECT name, enc_name, tags FROM videos ORDER BY date_added DESC")
        for row in cursor.fetchall():
            file_path = os.path.join(config.get("vault_path"), row[1])
            if os.path.exists(file_path):
                videos.append({
                    "id": row[1], 
                    "name": row[0], 
                    "size": os.path.getsize(file_path),
                    "tags": row[2] if row[2] else ""
                })
        conn.close()
    return jsonify(videos)

@app.route('/api/upload', methods=['POST'])
def upload_video():
    token = request.form.get('token')
    if token not in sessions or sessions[token]['ip'] != get_client_ip() or time.time() > sessions[token]['expires_at']:
        return jsonify({"error": "Unauthorized"}), 401
    
    file = request.files.get('file')
    custom_title = request.form.get('title', file.filename if file else 'Untitled')
    if not file: return jsonify({"error": "No file"}), 400

    config = get_vault_config()
    pwd = sessions[token]['password']
    vault_path = config.get("vault_path")
    enc_filename = secrets.token_hex(16) + ".enc"
    save_path = os.path.join(vault_path, enc_filename)

    try:
        key = derive_key_python(pwd, config['salt'])
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(key).encrypt(nonce, file.read(), None)
        with open(save_path, 'wb') as f:
            f.write(nonce + ciphertext)
            
        # Generate Thumbnail
        thumb_filename = enc_filename + ".thumb.enc"
        thumb_path = os.path.join(vault_path, thumb_filename)
        generate_thumbnail_encrypted(save_path, thumb_path, key)

        tags = request.form.get('tags', '')
        
        conn = sqlite3.connect(os.path.join(vault_path, "vault.db"))
        conn.execute("INSERT INTO videos (name, enc_name, date_added, tags) VALUES (?, ?, ?, ?)", 
                    (custom_title, enc_filename, datetime.datetime.now().isoformat(), tags))
        conn.commit()
        conn.close()
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def generate_thumbnail_encrypted(video_enc_path, thumb_enc_path, key):
    try:
        # Decrypt video temporarily to memory/stream (Memory might be issue for large files, but CV2 needs random access)
        # For security, we decode a small chunk or use a temporary temp file if needed.
        # Since CV2 can't read from memory easily without custom I/O, we'll write a temp decrypted snippet.
        
        with open(video_enc_path, 'rb') as f:
            raw_data = f.read()
            
        nonce, ciphertext = raw_data[:12], raw_data[12:]
        decrypted_data = AESGCM(key).decrypt(nonce, ciphertext, None)
        
        temp_vid = "temp_vid_" + secrets.token_hex(4) + ".mp4"
        with open(temp_vid, 'wb') as f:
            f.write(decrypted_data)
            
        cap = cv2.VideoCapture(temp_vid)
        success, image = cap.read()
        cap.release()
        os.remove(temp_vid)
        
        if success:
             # Resize to max 480px width to save space/time
            h, w = image.shape[:2]
            if w > 480:
                scale = 480 / w
                new_h = int(h * scale)
                image = cv2.resize(image, (480, new_h), interpolation=cv2.INTER_AREA)

            # Lower quality
            success, buffer = cv2.imencode('.jpg', image, [int(cv2.IMWRITE_JPEG_QUALITY), 60])
            if success:
                thumb_data = buffer.tobytes()
                # Encrypt Thumbnail
                nonce_thumb = secrets.token_bytes(12)
                cipher_thumb = AESGCM(key).encrypt(nonce_thumb, thumb_data, None)
                with open(thumb_enc_path, 'wb') as f:
                    f.write(nonce_thumb + cipher_thumb)
                return True
    except Exception as e:
        print(f"Thumbnail generation failed: {e}")
    return False

@app.route('/api/thumbnail/<string:video_id>', methods=['GET'])
def get_thumbnail(video_id):
    token = request.args.get('token')
    if token not in sessions or sessions[token]['ip'] != get_client_ip() or time.time() > sessions[token]['expires_at']:
        return "Unauthorized", 401
    
    config = get_vault_config()
    pwd = sessions[token]['password']
    thumb_path = os.path.join(config.get("vault_path"), video_id + ".thumb.enc")
    
    # If no thumbnail exists, we could try to generate one on the fly, or return 404
    if not os.path.exists(thumb_path):
        return "No thumbnail", 404

    try:
        key = derive_key_python(pwd, config['salt'])
        with open(thumb_path, 'rb') as f:
            raw_data = f.read()
        nonce, ciphertext = raw_data[:12], raw_data[12:]
        decrypted_data = AESGCM(key).decrypt(nonce, ciphertext, None)
        return send_file(io.BytesIO(decrypted_data), mimetype='image/jpeg')
    except:
        return "Error", 500

@app.route('/api/tags', methods=['POST'])
def update_tags():
    token = request.json.get('token')
    if token not in sessions or sessions[token]['ip'] != get_client_ip() or time.time() > sessions[token]['expires_at']:
        return jsonify({"error": "Unauthorized"}), 401
    
    id = request.json.get('id')
    tags = request.json.get('tags')
    
    config = get_vault_config()
    db_path = os.path.join(config.get("vault_path"), "vault.db")
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE videos SET tags = ? WHERE enc_name = ?", (tags, id))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})

@app.route('/api/thumbnail-status', methods=['GET'])
def get_thumbnail_status():
    token = request.args.get('token')
    if token not in sessions or sessions[token]['ip'] != get_client_ip() or time.time() > sessions[token]['expires_at']:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(thumbnail_status)

def thumbnail_worker(videos, vault_path, key, force=False):
    global thumbnail_status
    thumbnail_status["is_running"] = True
    thumbnail_status["count"] = 0
    thumbnail_status["total"] = len(videos)
    thumbnail_status["errors"] = []

    for vid in videos:
        thumbnail_status["current"] = vid
        vid_path = os.path.join(vault_path, vid)
        thumb_path = os.path.join(vault_path, vid + ".thumb.enc")
        
        if os.path.exists(vid_path):
            if force or not os.path.exists(thumb_path):
                if generate_thumbnail_encrypted(vid_path, thumb_path, key):
                     thumbnail_status["count"] += 1
                else:
                     thumbnail_status["errors"].append(vid)
            else:
                 # Already exists and not forced
                 pass
            
    thumbnail_status["is_running"] = False
    thumbnail_status["current"] = "Done"

@app.route('/api/generate-thumbnails', methods=['POST'])
def generate_missing_thumbnails():
    token = request.json.get('token')
    if token not in sessions or sessions[token]['ip'] != get_client_ip() or time.time() > sessions[token]['expires_at']:
        return jsonify({"error": "Unauthorized"}), 401
    
    if thumbnail_status["is_running"]:
        return jsonify({"status": "already_running"})

    config = get_vault_config()
    pwd = sessions[token]['password']
    vault_path = config.get("vault_path")
    key = derive_key_python(pwd, config['salt'])
    
    conn = sqlite3.connect(os.path.join(vault_path, "vault.db"))
    cursor = conn.execute("SELECT enc_name FROM videos")
    videos = [row[0] for row in cursor.fetchall()]
    conn.close()
    
    # Filter only those missing thumbnails to avoid processing everything in the loop if possible, 
    # but the worker does the check too. Let's send all so the progress bar is accurate relative to checks? 
    # Or just send known missing? For simplicity, let the worker check existence, 
    # but pre-filtering gives a better "Total" count for the progress bar.
    
    missing_videos = []
    for vid in videos:
        if not os.path.exists(os.path.join(vault_path, vid + ".thumb.enc")):
            missing_videos.append(vid)
            
    if not missing_videos:
        return jsonify({"status": "success", "message": "No missing thumbnails"})

    thread = threading.Thread(target=thumbnail_worker, args=(missing_videos, vault_path, key))
    thread.daemon = True
    thread.start()
            
    return jsonify({"status": "started", "count": len(missing_videos)})

@app.route('/api/regenerate-thumbnails', methods=['POST'])
def regenerate_all_thumbnails():
    token = request.json.get('token')
    if token not in sessions or sessions[token]['ip'] != get_client_ip() or time.time() > sessions[token]['expires_at']:
        return jsonify({"error": "Unauthorized"}), 401
    
    if thumbnail_status["is_running"]:
        return jsonify({"status": "already_running"})

    config = get_vault_config()
    pwd = sessions[token]['password']
    vault_path = config.get("vault_path")
    key = derive_key_python(pwd, config['salt'])
    
    conn = sqlite3.connect(os.path.join(vault_path, "vault.db"))
    cursor = conn.execute("SELECT enc_name FROM videos")
    videos = [row[0] for row in cursor.fetchall()]
    conn.close()
    
    thread = threading.Thread(target=thumbnail_worker, args=(videos, vault_path, key, True))
    thread.daemon = True
    thread.start()
            
    return jsonify({"status": "started", "count": len(videos)})



@app.route('/api/add-bg', methods=['POST'])
def add_background():
    token = request.form.get('token')
    if token not in sessions or sessions[token]['ip'] != get_client_ip() or time.time() > sessions[token]['expires_at']:
        return jsonify({"error": "Unauthorized"}), 401
    
    file = request.files.get('file')
    if not file: return jsonify({"error": "No file"}), 400

    config = get_vault_config()
    pwd = sessions[token]['password']
    bg_dir = os.path.join(config.get("vault_path"), BG_DIR)
    if not os.path.exists(bg_dir): os.makedirs(bg_dir)
    
    bg_filename = secrets.token_hex(8) + ".enc"
    save_path = os.path.join(bg_dir, bg_filename)

    try:
        key = derive_key_python(pwd, config['salt'])
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(key).encrypt(nonce, file.read(), None)
        with open(save_path, 'wb') as f:
            f.write(nonce + ciphertext)
        return jsonify({"status": "success", "id": bg_filename})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/remove-bg', methods=['POST'])
def remove_background():
    token = request.json.get('token')
    bg_id = request.json.get('id')
    if token not in sessions or sessions[token]['ip'] != get_client_ip() or time.time() > sessions[token]['expires_at']:
        return jsonify({"error": "Unauthorized"}), 401
    
    config = get_vault_config()
    bg_path = os.path.join(config.get("vault_path"), BG_DIR, bg_id)
    if os.path.exists(bg_path):
        os.remove(bg_path)
    return jsonify({"status": "success"})

@app.route('/api/bg/<string:bg_id>', methods=['GET'])
def get_background_image(bg_id):
    token = request.args.get('token')
    if token not in sessions or sessions[token]['ip'] != get_client_ip() or time.time() > sessions[token]['expires_at']:
        return "Unauthorized", 401
    
    config = get_vault_config()
    pwd = sessions[token]['password']
    file_path = os.path.join(config.get("vault_path"), BG_DIR, bg_id)

    if not os.path.exists(file_path): return "Not found", 404

    try:
        key = derive_key_python(pwd, config['salt'])
        with open(file_path, 'rb') as f:
            raw_data = f.read()
        nonce, ciphertext = raw_data[:12], raw_data[12:]
        decrypted_data = AESGCM(key).decrypt(nonce, ciphertext, None)
        return send_file(io.BytesIO(decrypted_data), mimetype='image/jpeg')
    except:
        return "Error", 500

@app.route('/api/rename', methods=['POST'])
def rename_video():
    token = request.json.get('token')
    if token not in sessions or sessions[token]['ip'] != get_client_ip() or time.time() > sessions[token]['expires_at']:
        return jsonify({"error": "Unauthorized"}), 401
    
    id = request.json.get('id')
    new_name = request.json.get('name')
    config = get_vault_config()
    db_path = os.path.join(config.get("vault_path"), "vault.db")
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE videos SET name = ? WHERE enc_name = ?", (new_name, id))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})

@app.route('/api/video/<string:filename>', methods=['GET'])
def stream_video(filename):
    token = request.args.get('token')
    if token not in sessions or sessions[token]['ip'] != get_client_ip() or time.time() > sessions[token]['expires_at']:
        return "Unauthorized", 401
    
    config = get_vault_config()
    pwd = sessions[token]['password']
    file_path = os.path.join(config.get("vault_path"), filename)

    try:
        key = derive_key_python(pwd, config['salt'])
        with open(file_path, 'rb') as f:
            raw_data = f.read()
        nonce, ciphertext = raw_data[:12], raw_data[12:]
        decrypted_data = AESGCM(key).decrypt(nonce, ciphertext, None)
        return send_file(io.BytesIO(decrypted_data), mimetype='video/mp4')
    except Exception as e:
        return "Stream error", 500

# --- FRONTEND ---
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Vault Pro Secure</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
    <script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
    <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
        body { font-family: 'Inter', sans-serif; background-color: #000000; color: #ffffff; margin: 0; overflow-x: hidden; }
        .bg-layer { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: -1; background-size: cover; background-position: center; transition: opacity 2s ease-in-out; opacity: 0; }
        .bg-active { opacity: 0.35; }
        .thumb-overlay { background: linear-gradient(to top, rgba(0,0,0,0.8), transparent); }
    </style>
</head>
<body>
    <div id="root"></div>
    <script type="text/babel">
        const { useState, useEffect, useRef } = React;

        function App() {
            const [view, setView] = useState('loading'); 
            const [token, setToken] = useState(localStorage.getItem('vault_token'));
            const [password, setPassword] = useState('');
            const [videos, setVideos] = useState([]);
            const [filteredVideos, setFilteredVideos] = useState([]);
            const [error, setError] = useState('');
            const [expiryTime, setExpiryTime] = useState(0);
            const [timeLeft, setTimeLeft] = useState('');
            const [backgrounds, setBackgrounds] = useState([]);
            const [activeBgIdx, setActiveBgIdx] = useState(0);
            const [isUploading, setIsUploading] = useState(false);
            const [showSettings, setShowSettings] = useState(false);
            const [modal, setModal] = useState(null); 
            const [tempTitle, setTempTitle] = useState('');
            const [tempTags, setTempTags] = useState('');
            const [searchTerm, setSearchTerm] = useState('');
            const [genStatus, setGenStatus] = useState(null); 

            useEffect(() => { 
                checkAuth(); 
                const handleKey = (e) => { if (e.key === 'Escape') logout(); };
                window.addEventListener('keydown', handleKey);
                return () => window.removeEventListener('keydown', handleKey);
            }, []);

            useEffect(() => {
                if (view !== 'vault' || expiryTime === 0) return;
                const timer = setInterval(() => {
                    const diff = Math.max(0, Math.floor(expiryTime - (Date.now() / 1000)));
                    if (diff <= 0) { logout(); return; }
                    setTimeLeft(`${Math.floor(diff / 60)}m ${(diff % 60).toString().padStart(2, '0')}s`);
                }, 1000);
                return () => clearInterval(timer);
            }, [view, expiryTime]);

            useEffect(() => {
                if (backgrounds.length < 2) return;
                const interval = setInterval(() => {
                    setActiveBgIdx(prev => (prev + 1) % backgrounds.length);
                }, 10000); 
                return () => clearInterval(interval);
            }, [backgrounds]);

            useEffect(() => {
                const term = searchTerm.toLowerCase();
                setFilteredVideos(videos.filter(v => 
                    v.name.toLowerCase().includes(term) || 
                    (v.tags && v.tags.toLowerCase().includes(term))
                ));
            }, [searchTerm, videos]);

            useEffect(() => {
                let interval;
                if (genStatus && genStatus.is_running) {
                    interval = setInterval(async () => {
                        try {
                            const res = await fetch(`/api/thumbnail-status?token=${token}`);
                            if (res.ok) {
                                const status = await res.json();
                                setGenStatus(status);
                                if (!status.is_running) {
                                    loadVideos(token); // Refresh videos when done
                                }
                            }
                        } catch (e) { console.error(e); }
                    }, 1000);
                }
                return () => clearInterval(interval);
            }, [genStatus, token]);

            const checkAuth = async () => {
                const currentToken = localStorage.getItem('vault_token');
                if (!currentToken) { setView('login'); return; }
                try {
                    const res = await fetch('/api/status', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ token: currentToken })
                    }).then(r => r.json());
                    if (res.authenticated) {
                        setExpiryTime(res.expires_at);
                        setToken(currentToken);
                        setBackgrounds(res.backgrounds);
                        loadVideos(currentToken);
                        setView('vault');
                    } else { setView('login'); }
                } catch (e) { setView('login'); }
            };

            const loadVideos = async (authToken) => {
                const vids = await fetch('/api/videos', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ token: authToken })
                }).then(r => r.json());
                setVideos(vids);
            };

            const handleUnlock = async () => {
                const res = await fetch('/api/unlock', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ password })
                });
                const data = await res.json();
                if (res.ok) {
                    localStorage.setItem('vault_token', data.token);
                    window.location.reload();
                } else { setError(data.error); }
            };

            const logout = () => {
                localStorage.removeItem('vault_token');
                window.location.reload();
            };

            const confirmUpload = async () => {
                setIsUploading(true);
                const formData = new FormData();
                formData.append('file', modal.file);
                formData.append('token', token);
                formData.append('title', tempTitle);
                formData.append('tags', tempTags);
                setModal(null);
                try {
                    await fetch('/api/upload', { method: 'POST', body: formData });
                    loadVideos(token);
                } finally { setIsUploading(false); }
            };

            const handleAddBg = async (e) => {
                const file = e.target.files[0];
                if (!file) return;
                const formData = new FormData();
                formData.append('file', file);
                formData.append('token', token);
                const res = await fetch('/api/add-bg', { method: 'POST', body: formData }).then(r => r.json());
                if (res.status === 'success') {
                    setBackgrounds(prev => [...prev, res.id]);
                }
            };

            const removeBg = async (id) => {
                await fetch('/api/remove-bg', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ token, id })
                });
                setBackgrounds(prev => prev.filter(b => b !== id));
            };

            const generateThumbnails = async () => {
                setShowSettings(false);
                try {
                    const res = await fetch('/api/generate-thumbnails', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ token })
                    });
                    const data = await res.json();
                    if (data.status === 'started' || data.status === 'already_running') {
                        setGenStatus({ is_running: true, count: 0, total: 0, current: 'Initializing...' });
                    }
                } catch (e) {
                    setError("Failed to start generation");
                }
            };
            
            const confirmEdit = async () => {
                // Parallel update name and tags
                const p1 = fetch('/api/rename', {
                     method: 'POST',
                     headers: {'Content-Type': 'application/json'},
                     body: JSON.stringify({ token, id: modal.id, name: tempTitle })
                });
                const p2 = fetch('/api/tags', {
                     method: 'POST',
                     headers: {'Content-Type': 'application/json'},
                     body: JSON.stringify({ token, id: modal.id, tags: tempTags })
                });
                await Promise.all([p1, p2]);
                setModal(null);
                loadVideos(token);
            }

            const openSecurePlayer = (id) => {
                window.open(`/api/video/${id}?token=${token}`, "_blank");
            };

            if (view === 'loading') return <div className="p-8 text-orange-500">Initializing...</div>;

            return (
                <div>
                    {backgrounds.map((bgId, idx) => (
                        <div 
                            key={bgId}
                            className={`bg-layer ${idx === activeBgIdx ? 'bg-active' : ''}`}
                            style={{backgroundImage: `url("/api/bg/${bgId}?token=${token}")`}}
                        />
                    ))}
                    
                    {view === 'login' ? (
                        <div className="min-h-screen flex items-center justify-center p-4">
                            <div className="bg-[#111111]/80 backdrop-blur-md p-10 rounded-3xl border border-orange-600/20 w-full max-w-md shadow-2xl">
                                <h1 className="text-3xl font-bold mb-8 text-center text-orange-500 uppercase tracking-tighter">Vault Pro</h1>
                                <input type="password" placeholder="Master Password" autoFocus className="w-full bg-black p-4 rounded-xl mb-4 text-center border border-zinc-800 focus:border-orange-500 outline-none text-white" value={password} onChange={e => setPassword(e.target.value)} onKeyPress={e => e.key === 'Enter' && handleUnlock()}/>
                                {error && <p className="text-red-500 text-sm mb-4 text-center">{error}</p>}
                                <button onClick={handleUnlock} className="w-full bg-orange-600 text-black p-4 rounded-xl font-black uppercase tracking-widest hover:bg-orange-500 transition-colors">Unlock</button>
                            </div>
                        </div>
                    ) : (
                        <div className="p-8 max-w-7xl mx-auto min-h-screen relative z-10">
                            <div className="flex flex-col md:flex-row justify-between items-center mb-10 border-b border-orange-600/20 pb-8 gap-4">
                                <div>
                                    <h1 className="text-4xl font-black uppercase tracking-tighter text-orange-500">Library</h1>
                                    <div className="text-orange-400 text-xs font-bold mt-2">SESSION: {timeLeft}</div>
                                </div>
                                <div className="flex-1 max-w-md w-full">
                                    <div className="relative">
                                        <svg className="absolute left-4 top-1/2 -translate-y-1/2 text-zinc-500" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
                                        <input className="w-full bg-zinc-900/50 border border-zinc-800 focus:border-orange-500 rounded-xl py-3 pl-12 pr-4 text-sm text-white outline-none transition-all placeholder-zinc-600" placeholder="Search videos or tags..." value={searchTerm} onChange={e => setSearchTerm(e.target.value)} />
                                    </div>
                                </div>
                                <div className="flex gap-4 items-center">
                                    <div className="relative">
                                        <button onClick={() => setShowSettings(!showSettings)} className="p-3 bg-zinc-900 border border-zinc-800 rounded-xl text-zinc-400 hover:text-orange-500 transition-colors">
                                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
                                        </button>
                                        {showSettings && (
                                            <div className="absolute right-0 mt-2 w-72 bg-[#111111] border border-zinc-800 rounded-2xl p-4 shadow-2xl z-50">
                                                <div className="mb-4">
                                                    <h4 className="text-xs font-black uppercase text-zinc-500 mb-2 tracking-widest">Maintenance</h4>
                                                    <button onClick={generateThumbnails} className="w-full text-left p-2 hover:bg-zinc-800 rounded-lg text-xs font-bold text-orange-500 transition-colors">
                                                        Generate Missing Thumbnails
                                                    </button>
                                                    <button onClick={() => { setShowSettings(false); fetch('/api/regenerate-thumbnails', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ token }) }).then(r => r.json()).then(d => { if (d.status === 'started' || d.status === 'already_running') setGenStatus({ is_running: true, count: 0, total: 0, current: 'Initializing...' }); }); }} className="w-full text-left p-2 hover:bg-zinc-800 rounded-lg text-xs font-bold text-red-500 transition-colors">
                                                        Regenerate All Thumbnails
                                                    </button>
                                                </div>
                                                <h4 className="text-xs font-black uppercase text-zinc-500 mb-3 tracking-widest">Backgrounds</h4>
                                                <div className="max-h-48 overflow-y-auto mb-4 space-y-2">
                                                    {backgrounds.map(bgId => (
                                                        <div key={bgId} className="flex items-center gap-3 p-2 bg-zinc-900/50 rounded-lg group">
                                                            <img src={`/api/bg/${bgId}?token=${token}`} className="w-10 h-10 object-cover rounded-md border border-zinc-800" />
                                                            <button onClick={() => removeBg(bgId)} className="ml-auto text-zinc-600 hover:text-red-500 transition-colors">
                                                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><path d="M3 6h18"></path><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"></path><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"></path></svg>
                                                            </button>
                                                        </div>
                                                    ))}
                                                    {backgrounds.length === 0 && <p className="text-[10px] text-zinc-700 uppercase italic">No custom images</p>}
                                                </div>
                                                <label className="flex items-center justify-center gap-2 p-3 bg-zinc-800 hover:bg-zinc-700 rounded-xl cursor-pointer text-xs font-bold text-zinc-300 transition-all">
                                                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
                                                    Add Slide
                                                    <input type="file" className="hidden" accept="image/*" onChange={handleAddBg} />
                                                </label>
                                            </div>
                                        )}
                                    </div>
                                    <label className="cursor-pointer px-6 py-3 bg-orange-600 text-black rounded-xl font-bold uppercase text-sm hover:bg-orange-500 transition-colors whitespace-nowrap">
                                        {isUploading ? 'Encrypting...' : 'Add Video'}
                                        <input type="file" className="hidden" accept="video/*" disabled={isUploading} onChange={(e) => {
                                            const file = e.target.files[0];
                                            if (!file) return;
                                            setTempTitle(file.name.split('.').slice(0, -1).join('.'));
                                            setTempTags('');
                                            setModal({ type: 'upload', file });
                                        }} />
                                    </label>
                                    <button onClick={logout} className="px-6 py-3 bg-zinc-900 border border-orange-600/30 rounded-xl text-orange-500 font-bold uppercase text-sm hover:bg-zinc-800 transition-colors">Lock</button>
                                </div>
                            </div>

                            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
                                {filteredVideos.length === 0 && (
                                    <div className="col-span-full py-20 text-center text-zinc-600 font-bold uppercase tracking-widest border-2 border-dashed border-zinc-900 rounded-3xl">
                                        {videos.length === 0 ? "Vault is empty" : "No matches found"}
                                    </div>
                                )}
                                {filteredVideos.map(v => (
                                    <div key={v.id} className="bg-[#111111]/60 backdrop-blur-sm border border-zinc-900 p-6 rounded-3xl group hover:border-orange-500/50 transition-all shadow-xl">
                                        <div className="aspect-video bg-black rounded-2xl mb-4 text-zinc-800 group-hover:text-orange-500 transition-colors relative overflow-hidden group/img">
                                            <img
                                                src={`/api/thumbnail/${v.id}?token=${token}`}
                                                className="w-full h-full object-cover opacity-80 group-hover/img:opacity-100 transition-opacity"
                                                onError={(e) => {
                                                    e.target.style.display='none';
                                                    e.target.nextSibling.style.display='flex';
                                                }}
                                            />
                                            <div className="hidden absolute inset-0 items-center justify-center bg-zinc-900">
                                                <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
                                            </div>
                                            <div className="absolute inset-0 bg-black/60 opacity-0 group-hover/img:opacity-100 transition-opacity flex items-center justify-center pointer-events-none">
                                                <svg className="text-orange-500" width="48" height="48" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
                                            </div>
                                            <button onClick={() => openSecurePlayer(v.id)} className="absolute inset-0 z-10"></button>
                                        </div>
                                        <div className="mb-4">
                                            <div className="flex justify-between items-start">
                                                <h3 className="font-bold truncate pr-2 text-white">{v.name}</h3>
                                                <button onClick={() => { setTempTitle(v.name); setTempTags(v.tags || ''); setModal({type:'edit', id: v.id}) }} className="text-zinc-600 hover:text-orange-500 transition-colors">
                                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
                                                </button>
                                            </div>
                                            <div className="flex flex-wrap gap-1 mt-2">
                                                {v.tags && v.tags.split(',').filter(t => t.trim()).map(t => (
                                                    <span key={t} className="text-[10px] uppercase font-bold px-2 py-1 bg-zinc-800 rounded-md text-zinc-400">{t.trim()}</span>
                                                ))}
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>

                            {modal && (
                                <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
                                    <div className="bg-[#111111] border border-orange-500/30 p-8 rounded-3xl w-full max-w-sm shadow-2xl">
                                        <h2 className="text-xl font-black uppercase text-orange-500 mb-4">
                                            {modal.type === 'upload' ? 'Finalize Upload' : 'Edit Video'}
                                        </h2>
                                        
                                        <p className="text-zinc-500 text-xs mb-2 uppercase font-bold">Video Title</p>
                                        <input autoFocus className="w-full bg-black border border-zinc-800 p-4 rounded-xl text-white outline-none focus:border-orange-500 mb-4" value={tempTitle} onChange={e => setTempTitle(e.target.value)} onKeyPress={e => e.key === 'Enter' && (modal.type === 'upload' ? confirmUpload() : confirmEdit())}/>
                                        
                                        <p className="text-zinc-500 text-xs mb-2 uppercase font-bold">Tags (Comma Separated)</p>
                                        <input className="w-full bg-black border border-zinc-800 p-4 rounded-xl text-white outline-none focus:border-orange-500 mb-6" placeholder="e.g. family, vacation, 2024" value={tempTags} onChange={e => setTempTags(e.target.value)} onKeyPress={e => e.key === 'Enter' && (modal.type === 'upload' ? confirmUpload() : confirmEdit())}/>
                                        
                                        <div className="flex gap-3">
                                            <button onClick={() => setModal(null)} className="flex-1 py-3 bg-zinc-900 rounded-xl font-bold text-zinc-500 uppercase text-xs hover:bg-zinc-800 transition-colors">Cancel</button>
                                            <button onClick={modal.type === 'upload' ? confirmUpload : confirmEdit} className="flex-1 py-3 bg-orange-600 rounded-xl font-bold text-black uppercase text-xs hover:bg-orange-500 transition-colors">Save</button>
                                        </div>
                                    </div>
                                </div>
                            )}
                            
                            {genStatus && (
                                <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
                                    <div className="bg-[#111111] border border-orange-500/30 p-8 rounded-3xl w-full max-w-sm shadow-2xl text-center">
                                        <h2 className="text-xl font-black uppercase text-orange-500 mb-4">
                                            {genStatus.is_running ? 'Generating Thumbnails...' : 'Generation Complete'}
                                        </h2>
                                        
                                        <div className="mb-6">
                                            {genStatus.is_running ? (
                                                <div className="animate-pulse">
                                                    <p className="text-zinc-400 text-sm mb-2">Processing: <span className="text-white font-bold">{genStatus.current}</span></p>
                                                    <div className="w-full bg-zinc-900 rounded-full h-2 mb-2">
                                                        <div className="bg-orange-600 h-2 rounded-full transition-all duration-300" style={{width: `${(genStatus.count / (genStatus.total || 1)) * 100}%`}}></div>
                                                    </div>
                                                    <p className="text-xs text-zinc-500">{genStatus.count} / {genStatus.total}</p>
                                                </div>
                                            ) : (
                                                <div>
                                                    <p className="text-zinc-300 mb-4">Processed {genStatus.total} videos.</p>
                                                    {genStatus.errors && genStatus.errors.length > 0 && (
                                                        <div className="text-red-500 text-xs text-left bg-red-900/10 p-2 rounded-lg mb-4 max-h-32 overflow-y-auto">
                                                            <p className="font-bold mb-1">Errors:</p>
                                                            {genStatus.errors.map(e => <div key={e}>{e}</div>)}
                                                        </div>
                                                    )}
                                                </div>
                                            )}
                                        </div>
                                        
                                        {!genStatus.is_running && (
                                            <button onClick={() => setGenStatus(null)} className="w-full py-3 bg-orange-600 rounded-xl font-bold text-black uppercase text-xs hover:bg-orange-500 transition-colors">
                                                Close
                                            </button>
                                        )}
                                    </div>
                                </div>
                            )}
                        </div>
                    )}
                </div>
            );
        }

        const root = ReactDOM.createRoot(document.getElementById('root'));
        root.render(<App />);
    </script>
</body>
</html>
'''

if __name__ == '__main__':
    generate_self_signed_cert()
    app.run(host='0.0.0.0', port=49847, ssl_context=(CERT_FILE, KEY_FILE), threaded=True)
