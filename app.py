from flask import Flask, render_template, request, redirect, url_for, session, flash, g, jsonify, send_from_directory
import sqlite3
from datetime import datetime
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import smtplib
from email.mime.text import MIMEText
import requests
import random
import time

DATABASE = 'vending.db'
UPLOAD_FOLDER = 'static/deposit_images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

def send_verification_email(to_email, token):
    smtp_host = "smtp.gmail.com"
    smtp_port = 587
    smtp_user = "koty0516@gmail.com"
    smtp_pass = "idmfpaxsklkmtshh"
    subject = "이메일 인증 - 포인트 자판기"
    body = f"이메일 인증을 위해 아래 링크를 클릭하세요:\n\nhttp://127.0.0.1:5000/verify_email?token={token}"
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = smtp_user
    msg['To'] = to_email
    try:
        s = smtplib.SMTP(smtp_host, smtp_port)
        s.starttls()
        s.login(smtp_user, smtp_pass)
        s.sendmail(smtp_user, [to_email], msg.as_string())
        s.quit()
    except Exception as e:
        print("메일 전송 실패:", e)

def send_reset_email(to_email, token):
    smtp_host = "smtp.gmail.com"
    smtp_port = 587
    smtp_user = "koty0516@gmail.com"
    smtp_pass = "idmfpaxsklkmtshh"
    subject = "비밀번호 재설정 - 포인트 자판기"
    body = f"비밀번호 재설정을 위해 아래 링크를 클릭하세요:\n\nhttp://127.0.0.1:5000/reset_password?token={token}"
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = smtp_user
    msg['To'] = to_email
    try:
        s = smtplib.SMTP(smtp_host, smtp_port)
        s.starttls()
        s.login(smtp_user, smtp_pass)
        s.sendmail(smtp_user, [to_email], msg.as_string())
        s.quit()
    except Exception as e:
        print("메일 전송 실패:", e)

def send_findid_email(to_email, username):
    smtp_host = "smtp.gmail.com"
    smtp_port = 587
    smtp_user = "koty0516@gmail.com"
    smtp_pass = "idmfpaxsklkmtshh"
    subject = "아이디 찾기 결과 - 포인트 자판기"
    body = f"회원님의 아이디(Username)는: {username}\n\n감사합니다."
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = smtp_user
    msg['To'] = to_email
    try:
        s = smtplib.SMTP(smtp_host, smtp_port)
        s.starttls()
        s.login(smtp_user, smtp_pass)
        s.sendmail(smtp_user, [to_email], msg.as_string())
        s.quit()
    except Exception as e:
        print("ID메일 전송 실패:", e)

def create_admin_if_not_exists():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    admin = db.execute("SELECT * FROM users WHERE username = ?", ('pee',)).fetchone()
    if not admin:
        password_hash = generate_password_hash('pee')
        db.execute(
            "INSERT INTO users (username, password, password_hash, email, email_verified, points) VALUES (?, ?, ?, ?, ?, ?)",
            ('pee', 'pee', password_hash, 'admin@admin.com', 1, 0)
        )
        db.commit()
    db.close()

def init_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            password_hash TEXT,
            email TEXT,
            email_verified INTEGER DEFAULT 0,
            points INTEGER DEFAULT 0
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            price INTEGER,
            stock INTEGER
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS purchases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            product_id INTEGER,
            quantity INTEGER,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(product_id) REFERENCES products(id)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            product_id INTEGER,
            content TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(product_id) REFERENCES products(id)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS notice (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            content TEXT
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS charge_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            depositor TEXT,
            amount INTEGER,
            status TEXT DEFAULT '대기중',
            requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            approved_at TIMESTAMP,
            deposit_image TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS email_verifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            token TEXT,
            is_verified INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            token TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS coupons (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE,
            description TEXT,
            max_uses INTEGER,
            used_count INTEGER DEFAULT 0,
            amount INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS coupon_usages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            coupon_id INTEGER,
            used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(coupon_id) REFERENCES coupons(id)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS vending_access (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            allowed INTEGER DEFAULT 1,
            admin_pass TEXT DEFAULT 'admin'
        )
    """)
    if not db.execute("SELECT * FROM notice WHERE id=1").fetchone():
        db.execute("INSERT INTO notice (id, content) VALUES (1, '')")
    if not db.execute("SELECT * FROM vending_access WHERE id=1").fetchone():
        db.execute("INSERT INTO vending_access (id, allowed, admin_pass) VALUES (1, 1, 'admin')")
    db.commit()
    db.close()
    create_admin_if_not_exists()

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def is_vending_allowed():
    db = get_db()
    row = db.execute("SELECT allowed FROM vending_access WHERE id=1").fetchone()
    return bool(row["allowed"]) if row else True

def get_admin_pass():
    db = get_db()
    row = db.execute("SELECT admin_pass FROM vending_access WHERE id=1").fetchone()
    return row["admin_pass"] if row else "admin"

@app.route('/deposit_image/<filename>')
def deposit_image(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# -------------------------- PASS 본인인증 연동부 -------------------------------
PASS_API_URL = "https://svc.passauth.co.kr/api/v2/identity"  # 예시, 실제 서비스로 교체 필요
PASS_CLIENT_ID = "YOUR_PASS_CLIENT_ID"
PASS_CLIENT_SECRET = "YOUR_PASS_CLIENT_SECRET"

def verify_pass_auth(phone, name, birth):
    try:
        payload = {
            "client_id": PASS_CLIENT_ID,
            "client_secret": PASS_CLIENT_SECRET,
            "name": name,
            "birth": birth.replace("-", ""),
            "phone": phone,
        }
        resp = requests.post(PASS_API_URL, json=payload, timeout=10)
        if resp.status_code == 200:
            r = resp.json()
            return r.get("success", False) or (r.get("result_code") == "0000")
        else:
            print("PASS API 오류:", resp.status_code, resp.text)
            return False
    except Exception as e:
        print("PASS API 예외:", e)
        return False

# ------------------ SMS 인증번호 발송(SMS API 연동) ------------------
COOLSMS_API_KEY = "YOUR_COOLSMS_API_KEY"
COOLSMS_API_SECRET = "YOUR_COOLSMS_API_SECRET"
COOLSMS_SENDER = "01000000000"  # 쿨SMS 인증된 발신번호

def send_sms(phone, msg):
    url = "https://api.coolsms.co.kr/sms/2/send"
    payload = {
        "api_key": COOLSMS_API_KEY,
        "api_secret": COOLSMS_API_SECRET,
        "to": phone,
        "from": COOLSMS_SENDER,
        "text": msg,
        "type": "SMS"
    }
    try:
        resp = requests.post(url, data=payload)
        if resp.status_code == 200:
            r = resp.json()
            return r.get("success_count", 0) > 0
        else:
            print("SMS API 오류:", resp.status_code, resp.text)
            return False
    except Exception as e:
        print("SMS API 예외:", e)
        return False

# {전화번호: (인증번호, 만료시각)} 3분 제한
phone_auth_codes = {}

@app.route('/send_phone_code', methods=['POST'])
def send_phone_code():
    phone = request.form['phone']
    if not phone or not phone.isdigit():
        return jsonify({'ok': False, 'msg': '올바른 휴대폰번호를 입력하세요.'})
    code = str(random.randint(100000, 999999))
    msg = f"[포인트자판기] 인증번호: {code}"
    ok = send_sms(phone, msg)
    if ok:
        expire = int(time.time()) + 180  # 3분 후 만료
        phone_auth_codes[phone] = (code, expire)
        return jsonify({'ok': True, 'msg': '인증번호가 발송되었습니다.'})
    else:
        return jsonify({'ok': False, 'msg': '인증번호 발송에 실패했습니다.'})

def check_phone_code(phone, user_code):
    now = int(time.time())
    data = phone_auth_codes.get(phone)
    if not data:
        return False
    code, expire = data
    if now > expire:
        del phone_auth_codes[phone]
        return False
    if user_code == code:
        del phone_auth_codes[phone]
        return True
    return False

# -------------------------- 메인 페이지/구매/회원가입 등 -------------------------------

@app.route('/')
def index():
    if not session.get('is_admin'):
        if not is_vending_allowed():
            return render_template('vending_closed.html')
    db = get_db()
    products = db.execute("SELECT * FROM products").fetchall()
    purchases = []
    user = None
    notice = db.execute("SELECT content FROM notice WHERE id=1").fetchone()
    notice_content = notice["content"] if notice else ""
    if 'user_id' in session and session['user_id'] != 'pee':
        user = db.execute("SELECT * FROM users WHERE id=?", (session['user_id'],)).fetchone()
        purchases = db.execute("""
            SELECT p.*, pr.name, pr.price FROM purchases p
            JOIN products pr ON p.product_id = pr.id
            WHERE p.user_id=?
            ORDER BY p.timestamp DESC LIMIT 5
        """, (session['user_id'],)).fetchall()
    return render_template('index.html', products=products, purchases=purchases, user=user, notice_content=notice_content)

@app.route('/', methods=['POST'])
def buy():
    if not session.get('is_admin'):
        if not is_vending_allowed():
            return render_template('vending_closed.html')
    if 'user_id' not in session or session['user_id'] == 'pee':
        flash('로그인 후 이용하세요.', 'danger')
        return redirect(url_for('index'))
    product_id = request.form.get('product_id')
    try:
        quantity = int(request.form.get('quantity', 1))
    except Exception:
        quantity = 1
    if quantity < 1:
        flash('수량은 1개 이상이어야 합니다.', 'danger')
        return redirect(url_for('index'))
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (session['user_id'],)).fetchone()
    product = db.execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
    if not product or product['stock'] < quantity:
        flash('상품의 재고가 부족합니다.', 'danger')
        return redirect(url_for('index'))
    total_price = product['price'] * quantity
    if user['points'] < total_price:
        flash('포인트가 부족합니다.', 'danger')
        return redirect(url_for('index'))
    db.execute("INSERT INTO purchases (user_id, product_id, quantity) VALUES (?, ?, ?)", (user['id'], product_id, quantity))
    db.execute("UPDATE users SET points=points-? WHERE id=?", (total_price, user['id']))
    db.execute("UPDATE products SET stock=stock-? WHERE id=?", (quantity, product_id))
    db.commit()
    flash('구매가 완료되었습니다.', 'success')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if not is_vending_allowed() and not session.get('is_admin'):
        return render_template('vending_closed.html')
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        phone = request.form['phone']
        name = request.form['name']
        birth = request.form['birth']
        phone_code = request.form.get('phone_code')
        if not phone_code or not check_phone_code(phone, phone_code):
            flash('휴대폰 인증번호가 일치하지 않거나 만료되었습니다.', 'danger')
            return render_template('register.html')
        if not verify_pass_auth(phone, name, birth):
            flash('PASS 본인인증에 실패했습니다. 정보를 확인하거나, 본인명의 휴대폰으로 시도하세요.', 'danger')
            return render_template('register.html')
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=? OR email=?", (username, email)).fetchone()
        if user:
            flash('이미 존재하는 아이디 또는 이메일입니다.', 'danger')
            return render_template('register.html')
        password_hash = generate_password_hash(password)
        db.execute("INSERT INTO users (username, password, password_hash, email, email_verified, points) VALUES (?, ?, ?, ?, 0, 0)",
                   (username, password, password_hash, email))
        db.commit()
        user_id = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()['id']
        token = secrets.token_urlsafe(32)
        db.execute("INSERT INTO email_verifications (user_id, token) VALUES (?, ?)", (user_id, token))
        db.commit()
        send_verification_email(email, token)
        flash('회원가입이 완료되었습니다. 이메일 인증을 진행해주세요.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

# ------------ 이하 라우트 전체(로그인, 로그아웃, 아이디찾기, 비번찾기, 마이페이지, 관리자 등) 위 답변 참고해 모두 추가 ------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = (user['username'] == 'pee')
            flash('로그인 성공!', 'success')
            return redirect(url_for('index'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('로그아웃되었습니다.', 'success')
    return redirect(url_for('index'))

@app.route('/find_id', methods=['GET', 'POST'])
def find_id():
    if request.method == 'POST':
        email = request.form['email']
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user:
            send_findid_email(email, user['username'])
            flash('이메일로 아이디를 전송했습니다.', 'success')
        else:
            flash('해당 이메일로 가입된 사용자가 없습니다.', 'danger')
    return render_template('find_id.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=? AND email=?", (username, email)).fetchone()
        if user:
            token = secrets.token_urlsafe(32)
            db.execute("INSERT INTO password_resets (user_id, token) VALUES (?, ?)", (user['id'], token))
            db.commit()
            send_reset_email(email, token)
            flash('비밀번호 재설정 메일을 전송했습니다.', 'success')
        else:
            flash('일치하는 사용자가 없습니다.', 'danger')
    return render_template('forgot_password.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    token = request.args.get('token') or request.form.get('token')
    if not token:
        flash('토큰이 유효하지 않습니다.', 'danger')
        return redirect(url_for('login'))
    db = get_db()
    pr = db.execute("SELECT * FROM password_resets WHERE token=?", (token,)).fetchone()
    if not pr:
        flash('유효하지 않은 토큰입니다.', 'danger')
        return redirect(url_for('login'))
    if request.method == 'POST':
        newpw = request.form['password']
        user_id = pr['user_id']
        db.execute("UPDATE users SET password=?, password_hash=? WHERE id=?", (newpw, generate_password_hash(newpw), user_id))
        db.execute("DELETE FROM password_resets WHERE user_id=?", (user_id,))
        db.commit()
        flash('비밀번호가 변경되었습니다. 다시 로그인해주세요.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', token=token)

@app.route('/verify_email')
def verify_email():
    token = request.args.get('token')
    db = get_db()
    ver = db.execute("SELECT * FROM email_verifications WHERE token=?", (token,)).fetchone()
    if not ver:
        flash('잘못된 인증 링크입니다.', 'danger')
        return redirect(url_for('login'))
    db.execute("UPDATE users SET email_verified=1 WHERE id=?", (ver['user_id'],))
    db.execute("UPDATE email_verifications SET is_verified=1 WHERE token=?", (token,))
    db.commit()
    flash('이메일 인증이 완료되었습니다.', 'success')
    return redirect(url_for('login'))

@app.route('/my_purchases')
def my_purchases():
    if 'user_id' not in session or session.get('is_admin'):
        flash('로그인 후 이용해주세요.', 'danger')
        return redirect(url_for('login'))
    db = get_db()
    purchases = db.execute("""
        SELECT p.*, pr.name, pr.price FROM purchases p
        JOIN products pr ON p.product_id = pr.id
        WHERE p.user_id=?
        ORDER BY p.timestamp DESC
    """, (session['user_id'],)).fetchall()
    return render_template('my_purchases.html', purchases=purchases)

@app.route('/charge_request', methods=['GET', 'POST'])
def charge_request():
    if 'user_id' not in session or session.get('is_admin'):
        flash('로그인 후 이용해주세요.', 'danger')
        return redirect(url_for('login'))
    if request.method == 'POST':
        depositor = request.form['depositor']
        amount = int(request.form['amount'])
        image = request.files.get('deposit_image')
        filename = ""
        if image and allowed_file(image.filename):
            filename = secure_filename(f"{int(time.time())}_{image.filename}")
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        db = get_db()
        db.execute("INSERT INTO charge_requests (user_id, depositor, amount, deposit_image) VALUES (?, ?, ?, ?)",
                   (session['user_id'], depositor, amount, filename))
        db.commit()
        flash('충전 요청이 접수되었습니다.', 'success')
        return redirect(url_for('charge_history'))
    return render_template('charge_request.html')

@app.route('/charge_history')
def charge_history():
    if 'user_id' not in session or session.get('is_admin'):
        flash('로그인 후 이용해주세요.', 'danger')
        return redirect(url_for('login'))
    db = get_db()
    charges = db.execute("""
        SELECT * FROM charge_requests
        WHERE user_id=?
        ORDER BY requested_at DESC
    """, (session['user_id'],)).fetchall()
    return render_template('charge_history.html', charges=charges)

@app.route('/use_coupon', methods=['GET', 'POST'])
def use_coupon():
    if 'user_id' not in session or session.get('is_admin'):
        flash('로그인 후 이용해주세요.', 'danger')
        return redirect(url_for('login'))
    if request.method == 'POST':
        code = request.form['code']
        db = get_db()
        coupon = db.execute("SELECT * FROM coupons WHERE code=?", (code,)).fetchone()
        if not coupon:
            flash('유효하지 않은 쿠폰입니다.', 'danger')
        elif coupon['used_count'] >= coupon['max_uses']:
            flash('쿠폰 사용 가능 횟수를 초과하였습니다.', 'danger')
        else:
            used = db.execute("SELECT * FROM coupon_usages WHERE user_id=? AND coupon_id=?", (session['user_id'], coupon['id'])).fetchone()
            if used:
                flash('이미 사용한 쿠폰입니다.', 'danger')
            else:
                db.execute("UPDATE coupons SET used_count=used_count+1 WHERE id=?", (coupon['id'],))
                db.execute("INSERT INTO coupon_usages (user_id, coupon_id) VALUES (?, ?)", (session['user_id'], coupon['id']))
                db.execute("UPDATE users SET points=points+? WHERE id=?", (coupon['amount'], session['user_id']))
                db.commit()
                flash('쿠폰이 적용되었습니다.', 'success')
    return render_template('use_coupon.html')

@app.route('/reviews', methods=['GET', 'POST'])
def reviews():
    db = get_db()
    if request.method == 'POST':
        if 'user_id' not in session or session.get('is_admin'):
            flash('로그인 후 이용해주세요.', 'danger')
            return redirect(url_for('login'))
        content = request.form['content']
        product_id = int(request.form['product_id'])
        db.execute("INSERT INTO reviews (user_id, product_id, content) VALUES (?, ?, ?)", (session['user_id'], product_id, content))
        db.commit()
        flash('후기가 등록되었습니다.', 'success')
    reviews = db.execute("""
        SELECT r.*, u.username, p.name FROM reviews r
        JOIN users u ON r.user_id = u.id
        JOIN products p ON r.product_id = p.id
        ORDER BY r.created_at DESC
    """).fetchall()
    products = db.execute("SELECT * FROM products").fetchall()
    return render_template('reviews.html', reviews=reviews, products=products)

# ------------------- 관리자 라우트 -------------------

@app.route('/admin_products', methods=['GET', 'POST'])
def admin_products():
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    db = get_db()
    if request.method == 'POST':
        name = request.form['name']
        price = int(request.form['price'])
        stock = int(request.form['stock'])
        db.execute("INSERT INTO products (name, price, stock) VALUES (?, ?, ?)", (name, price, stock))
        db.commit()
        flash('상품이 등록되었습니다.', 'success')
    products = db.execute("SELECT * FROM products").fetchall()
    return render_template('admin_products.html', products=products)

@app.route('/admin_products/delete/<int:product_id>', methods=['POST'])
def admin_delete_product(product_id):
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    db = get_db()
    db.execute("DELETE FROM products WHERE id=?", (product_id,))
    db.commit()
    flash('상품이 삭제되었습니다.', 'success')
    return redirect(url_for('admin_products'))

@app.route('/admin_charge', methods=['GET', 'POST'])
def admin_charge():
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    db = get_db()
    if request.method == 'POST':
        charge_id = int(request.form['charge_id'])
        action = request.form['action']
        charge = db.execute("SELECT * FROM charge_requests WHERE id=?", (charge_id,)).fetchone()
        if not charge or charge['status'] != '대기중':
            flash('이미 처리된 요청입니다.', 'danger')
        else:
            if action == 'approve':
                db.execute("UPDATE charge_requests SET status='승인', approved_at=CURRENT_TIMESTAMP WHERE id=?", (charge_id,))
                db.execute("UPDATE users SET points=points+? WHERE id=?", (charge['amount'], charge['user_id']))
                db.commit()
                flash('충전이 승인되었습니다.', 'success')
            elif action == 'reject':
                db.execute("UPDATE charge_requests SET status='거절', approved_at=CURRENT_TIMESTAMP WHERE id=?", (charge_id,))
                db.commit()
                flash('충전이 거절되었습니다.', 'danger')
    charges = db.execute("""
        SELECT cr.*, u.username FROM charge_requests cr
        JOIN users u ON cr.user_id = u.id
        ORDER BY cr.requested_at DESC
    """).fetchall()
    return render_template('admin_charge.html', charges=charges)

@app.route('/admin_users')
def admin_users():
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    db = get_db()
    users = db.execute("SELECT * FROM users").fetchall()
    return render_template('admin_users.html', users=users)

@app.route('/admin_access', methods=['GET', 'POST'])
def admin_access():
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    db = get_db()
    if request.method == 'POST':
        allowed = 1 if request.form.get('allowed') == 'on' else 0
        admin_pass = request.form.get('admin_pass')
        db.execute("UPDATE vending_access SET allowed=?, admin_pass=? WHERE id=1", (allowed, admin_pass))
        db.commit()
        flash('설정이 저장되었습니다.', 'success')
    config = db.execute("SELECT * FROM vending_access WHERE id=1").fetchone()
    return render_template('admin_access.html', config=config)

@app.route('/admin_coupons', methods=['GET', 'POST'])
def admin_coupons():
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    db = get_db()
    if request.method == 'POST':
        code = request.form['code']
        desc = request.form['description']
        max_uses = int(request.form['max_uses'])
        amount = int(request.form['amount'])
        db.execute("INSERT INTO coupons (code, description, max_uses, amount) VALUES (?, ?, ?, ?)", (code, desc, max_uses, amount))
        db.commit()
        flash('쿠폰이 등록되었습니다.', 'success')
    coupons = db.execute("SELECT * FROM coupons").fetchall()
    return render_template('admin_coupons.html', coupons=coupons)

@app.route('/admin_purchases')
def admin_purchases():
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    db = get_db()
    purchases = db.execute("""
        SELECT p.*, u.username, pr.name as product_name FROM purchases p
        JOIN users u ON p.user_id = u.id
        JOIN products pr ON p.product_id = pr.id
        ORDER BY p.timestamp DESC
    """).fetchall()
    return render_template('admin_purchases.html', purchases=purchases)

@app.route('/admin_users/delete/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    db = get_db()
    db.execute("DELETE FROM users WHERE id=?", (user_id,))
    db.commit()
    flash('회원이 삭제되었습니다.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin_notice', methods=['GET', 'POST'])
def admin_notice():
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    db = get_db()
    if request.method == 'POST':
        content = request.form['content']
        db.execute("UPDATE notice SET content=? WHERE id=1", (content,))
        db.commit()
        flash('공지사항이 저장되었습니다.', 'success')
    notice = db.execute("SELECT * FROM notice WHERE id=1").fetchone()
    return render_template('admin_notice.html', notice=notice)

@app.route('/admin_reviews/delete/<int:review_id>', methods=['POST'])
def admin_delete_review(review_id):
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    db = get_db()
    db.execute("DELETE FROM reviews WHERE id=?", (review_id,))
    db.commit()
    flash('후기가 삭제되었습니다.', 'success')
    return redirect(url_for('reviews'))

@app.route('/admin_coupons/delete/<int:coupon_id>', methods=['POST'])
def admin_delete_coupon(coupon_id):
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    db = get_db()
    db.execute("DELETE FROM coupons WHERE id=?", (coupon_id,))
    db.commit()
    flash('쿠폰이 삭제되었습니다.', 'success')
    return redirect(url_for('admin_coupons'))

@app.route('/admin_products/stock/<int:product_id>', methods=['POST'])
def admin_update_stock(product_id):
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    new_stock = int(request.form['stock'])
    db = get_db()
    db.execute("UPDATE products SET stock=? WHERE id=?", (new_stock, product_id))
    db.commit()
    flash('재고가 수정되었습니다.', 'success')
    return redirect(url_for('admin_products'))

@app.route('/admin_products/price/<int:product_id>', methods=['POST'])
def admin_update_price(product_id):
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    new_price = int(request.form['price'])
    db = get_db()
    db.execute("UPDATE products SET price=? WHERE id=?", (new_price, product_id))
    db.commit()
    flash('가격이 수정되었습니다.', 'success')
    return redirect(url_for('admin_products'))

if __name__ == '__main__':
    init_db()
    app.run(host="0.0.0.0",port=2048)
