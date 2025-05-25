import sqlite3
import os

DATABASE = 'vending.db'
UPLOAD_FOLDER = 'static/deposit_images'

def init_db():
    db = sqlite3.connect(DATABASE)
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
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
            quantity INTEGER DEFAULT 1,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(product_id) REFERENCES products(id)
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
    # 공지사항 테이블
    db.execute("""
        CREATE TABLE IF NOT EXISTS notice (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            content TEXT
        )
    """)
    # 공지 row 준비
    if not db.execute("SELECT * FROM notice WHERE id=1").fetchone():
        db.execute("INSERT INTO notice (id, content) VALUES (1, '')")
    # 샘플 상품 없으면 추가
    if not db.execute("SELECT COUNT(*) FROM products").fetchone()[0]:
        db.executemany("INSERT INTO products (name, price, stock) VALUES (?, ?, ?)", [
            ("콜라", 1500, 10),
            ("사이다", 1400, 10),
            ("과자", 1200, 20),
            ("초콜릿", 1000, 15)
        ])
    db.commit()
    db.close()
    # 업로드 폴더 생성
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    print("DB 및 모든 테이블이 생성되었습니다.")

if __name__ == "__main__":
    init_db()