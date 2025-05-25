# 포인트 자판기 프로젝트

## 소개

이 프로젝트는 Flask와 SQLite를 기반으로 한 포인트 자판기 웹 애플리케이션입니다.  
회원가입, 이메일 인증, 포인트 충전, 제품 구매, 관리자 상품/회원/구매/쿠폰 관리 등 다양한 기능을 포함합니다.

---

## 설치 및 실행 방법

### 1. Python 및 pip 설치

- Python 3.8 이상이 필요합니다.
- [python.org](https://www.python.org/)에서 설치하세요.

### 2. 프로젝트 파일 준비

- `app.py`와 `templates/` 폴더 내의 모든 HTML 파일을 같은 폴더에 준비하세요.
- `static/deposit_images` 폴더가 없으면 자동 생성됩니다.

### 3. 필수 패키지 설치

터미널(명령 프롬프트)에서 아래 명령어로 필요한 패키지를 설치하세요.

```bash
pip install flask werkzeug
```

### 4. Gmail SMTP 설정 (이메일 인증/비밀번호 재설정 기능 사용시)

1. [구글 계정 2단계 인증](https://myaccount.google.com/security) 활성화
2. [앱 비밀번호](https://myaccount.google.com/apppasswords) 생성
3. `app.py`의 아래 부분을 실제 Gmail 주소와 앱 비밀번호로 수정

```python
smtp_user = "your_gmail@gmail.com"
smtp_pass = "여기에_앱_비밀번호"
```

- 자세한 방법은 [공식 가이드](https://support.google.com/accounts/answer/185833?hl=ko) 참고

### 5. 데이터베이스 초기화

- 서버를 처음 실행하면 자동으로 `vending.db` 파일 및 테이블이 생성됩니다.
- 관리자 계정은 자동 생성 (`아이디: pee`, `비밀번호: pee`)

### 6. 서버 실행

```bash
python app.py
```

- 실행 후 브라우저에서 [http://127.0.0.1:5000/](http://127.0.0.1:5000/) 접속

---

## 주요 기능

- **회원가입/로그인/이메일 인증/비밀번호 재설정**
- **제품 목록 조회·구매(포인트 차감)**
- **포인트 충전 요청 및 관리**
- **내 구매내역 확인**
- **후기 작성**
- **쿠폰 등록/사용**
- **관리자 페이지**
  - 제품 재고/가격/삭제 관리
  - 모든 회원 목록 및 포인트 관리
  - 전체 구매기록 열람
  - 충전 요청 관리
  - 쿠폰 관리
  - 공지사항 게시

---

## 폴더 구조 예시

```
project-root/
│
├─ app.py
├─ vending.db           # (자동생성)
├─ static/
│   └─ deposit_images/  # (자동생성)
└─ templates/
    ├─ index.html
    ├─ login.html
    ├─ register.html
    ├─ my_purchases.html
    ├─ admin_products.html
    ├─ admin_users.html
    ├─ admin_charge.html
    ├─ admin_notice.html
    ├─ admin_purchases.html
    ├─ admin_coupons.html
    ├─ use_coupon.html
    ├─ charge_history.html
    ├─ charge_request.html
    ├─ reviews.html
    ├─ forgot_password.html
    └─ reset_password.html
```

---

## 참고/문제 해결

- **데이터베이스 파일 삭제** 후 재실행 시 모든 데이터가 초기화됩니다.
- **이메일 발송이 안 될 경우:**
  - 앱 비밀번호가 정확한지, 2단계 인증이 켜져있는지 확인하세요.
  - Google SMTP 제한 정책(스팸 등)에 걸리지 않았는지 확인하세요.
- **포트 충돌 발생 시:** app.py에서 `app.run(debug=True, port=다른번호)`로 수정 가능

---

## 문의

- 문의/버그 제보: [프로젝트 관리자에게 메일 또는 이슈 등록]
