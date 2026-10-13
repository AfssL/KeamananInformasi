from __future__ import annotations
import os
import json
import secrets
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES, ARC4, DES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = Path('uploads')
app.config['CIPHER_FOLDER'] = Path('ciphertexts')

app.config['UPLOAD_FOLDER'].mkdir(exist_ok=True)
app.config['CIPHER_FOLDER'].mkdir(exist_ok=True)

db = SQLAlchemy(app)

SALT_SIZE = 16
AES_IV_SIZE = 16
DES_IV_SIZE = 8
PBKDF2_ROUNDS = 600_000
ALGORITHMS = {"AES", "DES", "RC4"}

# Database Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    files = db.relationship('EncryptedFile', backref='owner', lazy=True)

class EncryptedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    file_type = db.Column(db.String(50), nullable=False) # e.g., KTP, Document, Video
    algorithm = db.Column(db.String(10), nullable=False)
    envelope_path = db.Column(db.String(300), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

with app.app_context():
    db.create_all()

# Fungsi Kriptografi
def derive_key(password: str, salt: bytes, length: int) -> bytes:
    return PBKDF2(password, salt, dkLen=length, count=PBKDF2_ROUNDS, hmac_hash_module=SHA256)

def pkcs7pad(data: bytes, block_size: int) -> bytes:
    padding = block_size - len(data) % block_size
    return data + bytes([padding]) * padding

def pkcs7unpad(data: bytes, block_size: int) -> bytes:
    padding = data[-1]
    return data[:-padding]

def encrypt_data(data: bytes, password: str, algorithm: str, name: str) -> str:
    algorithm = algorithm.upper()
    salt = secrets.token_bytes(SALT_SIZE)
    fields = {"algorithm": algorithm, "name": name, "salt": base64_encode(salt)}

    if algorithm == "AES":
        key = derive_key(password, salt, 32)
        iv = secrets.token_bytes(AES_IV_SIZE)
        ciphertext = AES.new(key, AES.MODE_CBC, iv=iv).encrypt(pkcs7pad(data, AES.block_size))
        fields.update(iv=base64_encode(iv), ciphertext=base64_encode(ciphertext))
    elif algorithm == "DES":
        key = derive_key(password, salt, 8)
        iv = secrets.token_bytes(DES_IV_SIZE)
        ciphertext = DES.new(key, DES.MODE_CBC, iv=iv).encrypt(pkcs7pad(data, DES.block_size))
        fields.update(iv=base64_encode(iv), ciphertext=base64_encode(ciphertext))
    else: # RC4
        key = derive_key(password, salt, 32)
        ciphertext = ARC4.new(key).encrypt(data)
        fields.update(ciphertext=base64_encode(ciphertext))

    return json.dumps(fields)

def decrypt_data(envelope_content: str, password: str) -> tuple[bytes, str]:
    fields = json.loads(envelope_content)
    algorithm = fields["algorithm"].upper()
    salt = base64_decode(fields["salt"])
    ciphertext = base64_decode(fields["ciphertext"])
    iv = base64_decode(fields["iv"]) if algorithm in {"AES", "DES"} else b""

    if algorithm == "AES":
        key = derive_key(password, salt, 32)
        data = pkcs7unpad(AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ciphertext), AES.block_size)
    elif algorithm == "DES":
        key = derive_key(password, salt, 8)
        data = pkcs7unpad(DES.new(key, DES.MODE_CBC, iv=iv).decrypt(ciphertext), DES.block_size)
    else:
        key = derive_key(password, salt, 32)
        data = ARC4.new(key).decrypt(ciphertext)
    return data, fields.get("name", "file")

import base64
def base64_encode(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def base64_decode(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

# Routes Web
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login berhasil!', 'success')
            return redirect(url_for('dashboard'))
        flash('Username atau password salah!', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username sudah terdaftar!', 'danger')
        else:
            hashed_pw = generate_password_hash(password)
            new_user = User(username=username, password_hash=hashed_pw)
            db.session.add(new_user)
            db.session.commit()
            flash('Registrasi berhasil, silakan login.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        file = request.files.get('file')
        file_type = request.form.get('file_type')
        algorithm = request.form.get('algorithm')
        password = request.form.get('password')

        if file and password:
            filename = file.filename
            file_bytes = file.read()
            
            # Enkripsi data sesuai algoritma yang dipilih (AES / DES / RC4)
            envelope_json = encrypt_data(file_bytes, password, algorithm, filename)
            
            # Simpan envelope ke folder ciphertexts
            env_filename = f"{secrets.token_hex(8)}_{filename}.{algorithm.lower()}.json"
            env_path = app.config['CIPHER_FOLDER'] / env_filename
            env_path.write_text(envelope_json, encoding='utf-8')

            # Catat ke database
            new_file = EncryptedFile(
                filename=filename,
                file_type=file_type,
                algorithm=algorithm,
                envelope_path=str(env_path),
                user_id=session['user_id']
            )
            db.session.add(new_file)
            db.session.commit()
            flash(f'File berhasil diunggah dan dienkripsi dengan {algorithm}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Harap lengkapi file dan password enkripsi!', 'danger')

    user_files = EncryptedFile.query.filter_by(user_id=session['user_id']).all()
    return render_template('dashboard.html', files=user_files)

@app.route('/decrypt/<int:file_id>', methods=['POST'])
def decrypt_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    file_record = EncryptedFile.query.get_or_404(file_id)
    if file_record.user_id != session['user_id']:
        flash('Akses ditolak!', 'danger')
        return redirect(url_for('dashboard'))

    password = request.form.get('password')
    try:
        env_content = Path(file_record.envelope_path).read_text(encoding='utf-8')
        decrypted_bytes, original_name = decrypt_data(env_content, password)
        
        output_path = app.config['UPLOAD_FOLDER'] / original_name
        output_path.write_bytes(decrypted_bytes)
        
        return send_file(output_path, as_attachment=True)
    except Exception:
        flash('Password salah atau file terkorupsi!', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)