from flask import Flask, render_template, request, redirect, url_for, session, flash, g, jsonify, send_from_directory
import sqlite3
from datetime import datetime
import os
from werkzeug.utils import secure_filename

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

def init_db():
    import init_db as _init
    _init.init_db()
    db = sqlite3.connect(DATABASE)
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
    try:
        db.execute("ALTER TABLE charge_requests ADD COLUMN deposit_image TEXT")
    except sqlite3.OperationalError:
        pass
    if not db.execute("SELECT * FROM notice WHERE id=1").fetchone():
        db.execute("INSERT INTO notice (id, content) VALUES (1, '')")
        db.commit()
    db.close()

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.route('/deposit_image/<filename>')
def deposit_image(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/')
def index():
    db = get_db()
    products = db.execute("SELECT * FROM products").fetchall()
    purchases = []
    user = None
    notice = db.execute("SELECT content FROM notice WHERE id=1").fetchone()
    notice_content = notice["content"] if notice else ""
    if 'user_id' in session and session['user_id'] != 'admin':
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
    if 'user_id' not in session or session['user_id'] == 'admin':
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

@app.route('/admin_products', methods=['GET', 'POST'])
def admin_products():
    if not session.get('is_admin'):
        flash('관리자만 접근 가능합니다.', 'danger')
        return redirect(url_for('login'))
    db = get_db()
    if request.method == 'POST':
        for key in request.form:
            if key.startswith('stock_'):
                product_id = key.replace('stock_', '')
                stock = request.form[key]
                try:
                    stock = int(stock)
                    db.execute("UPDATE products SET stock=? WHERE id=?", (stock, product_id))
                except Exception:
                    pass
        db.commit()
        flash('재고가 수정되었습니다.', 'success')
        return redirect(url_for('admin_products'))
    products = db.execute("SELECT * FROM products").fetchall()
    return render_template('admin_products.html', products=products)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        try:
            db.execute("INSERT INTO users (username, password, points) VALUES (?, ?, ?)", (username, password, 0))
            db.commit()
            flash('회원가입이 완료되었습니다. 로그인하세요.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('이미 존재하는 아이디입니다.', 'danger')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # 관리자 계정 체크
        if username == 'admin' and password == 'admin':
            session['user_id'] = 'admin'
            session['is_admin'] = True
            flash('관리자로 로그인되었습니다.', 'success')
            return redirect(url_for('index'))

        # 일반 유저의 로그인 처리
        user = get_db().execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username, password)
        ).fetchone()
        if user:
            session['user_id'] = user['id']
            session['is_admin'] = False
            flash('로그인 성공', 'success')
            return redirect(url_for('index'))
        else:
            flash('로그인 실패', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('로그아웃되었습니다.', 'info')
    return redirect(url_for('index'))

@app.route('/my_purchases')
def my_purchases():
    if 'user_id' not in session or session['user_id'] == 'admin':
        flash('로그인 후 이용하세요.', 'danger')
        return redirect(url_for('login'))
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (session['user_id'],)).fetchone()
    purchases = db.execute("""
        SELECT p.*, pr.name, pr.price FROM purchases p
        JOIN products pr ON p.product_id = pr.id
        WHERE p.user_id=?
        ORDER BY p.timestamp DESC
    """, (session['user_id'],)).fetchall()
    return render_template('my_purchases.html', purchases=purchases, user=user)

@app.route('/charge_request', methods=['GET', 'POST'])
def charge_request():
    if request.method == 'GET':
        return render_template('charge_request.html')
    # POST
    if 'user_id' not in session or session['user_id'] == 'admin':
        return jsonify({'ok': False, 'msg': '로그인 필요'})
    depositor = request.form.get('depositor')
    amount = request.form.get('amount')
    file = request.files.get('deposit_image')
    deposit_image = None
    if file and allowed_file(file.filename):
        filename = secure_filename(f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}")
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        deposit_image = filename
    db = get_db()
    db.execute("INSERT INTO charge_requests (user_id, depositor, amount, deposit_image) VALUES (?, ?, ?, ?)",
               (session['user_id'], depositor, amount, deposit_image))
    db.commit()
    return jsonify({'ok': True})

@app.route('/admin_charge', methods=['GET', 'POST'])
def admin_charge():
    if not session.get('is_admin'):
        flash('관리자만 접근 가능합니다.', 'danger')
        return redirect(url_for('login'))
    db = get_db()
    if request.method == 'POST':
        req_id = request.form.get('req_id')
        action = request.form.get('action')
        if req_id and action:
            req = db.execute("SELECT * FROM charge_requests WHERE id=?", (req_id,)).fetchone()
            if req and req['status'] == '대기중':
                if action == 'approve':
                    db.execute("UPDATE users SET points = points + ? WHERE id = ?", (req['amount'], req['user_id']))
                    db.execute("UPDATE charge_requests SET status='완료', approved_at=? WHERE id=?",
                               (datetime.now(), req_id))
                    db.commit()
                    flash("충전 승인 완료", "success")
                elif action == 'reject':
                    db.execute("UPDATE charge_requests SET status='거절', approved_at=? WHERE id=?",
                               (datetime.now(), req_id))
                    db.commit()
                    flash("충전 요청이 거절되었습니다.", "info")
    requests = db.execute("""
        SELECT cr.*, u.username 
        FROM charge_requests cr 
        JOIN users u ON cr.user_id = u.id
        WHERE cr.status='대기중' ORDER BY cr.requested_at DESC
    """).fetchall()
    notice = db.execute("SELECT content FROM notice WHERE id=1").fetchone()
    notice_content = notice["content"] if notice else ""
    return render_template("admin_charge.html", requests=requests, notice_content=notice_content)

@app.route('/admin_notice', methods=['POST'])
def admin_notice():
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    content = request.form.get('notice_content', '')
    db = get_db()
    db.execute("UPDATE notice SET content=? WHERE id=1", (content,))
    db.commit()
    flash("공지사항이 수정되었습니다.", "success")
    return redirect(url_for('admin_charge'))

@app.route('/reviews', methods=['GET', 'POST'])
def reviews():
    db = get_db()
    user_id = session.get('user_id')
    can_review = False
    user_products = []
    if user_id and user_id != 'admin':
        user_products = db.execute("""
            SELECT DISTINCT pr.id, pr.name
            FROM purchases p
            JOIN products pr ON p.product_id = pr.id
            WHERE p.user_id=?
        """, (user_id,)).fetchall()
        can_review = bool(user_products)
    if request.method == 'POST':
        if not user_id or user_id == 'admin':
            flash('로그인 후 이용하세요.', 'danger')
            return redirect(url_for('reviews'))
        product_id = request.form.get('product_id')
        content = request.form.get('content')
        purchased = db.execute(
            "SELECT * FROM purchases WHERE user_id=? AND product_id=?",
            (user_id, product_id)
        ).fetchone()
        if not purchased:
            flash('해당 상품을 구매한 경우만 후기를 남길 수 있습니다.', 'danger')
        elif not content.strip():
            flash('후기 내용을 입력하세요.', 'danger')
        else:
            db.execute("INSERT INTO reviews (user_id, product_id, content) VALUES (?, ?, ?)",
                       (user_id, product_id, content))
            db.commit()
            flash('구매후기가 등록되었습니다.', 'success')
        return redirect(url_for('reviews'))
    reviews = db.execute("""
        SELECT r.*, u.username, p.name as product_name
        FROM reviews r
        JOIN users u ON r.user_id = u.id
        JOIN products p ON r.product_id = p.id
        ORDER BY r.created_at DESC
    """).fetchall()
    return render_template('reviews.html', reviews=reviews, can_review=can_review, user_products=user_products)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)