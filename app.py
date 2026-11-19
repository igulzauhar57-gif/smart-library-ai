from flask import Flask, render_template, request, jsonify, redirect, url_for, session, make_response
import sqlite3, os, datetime, secrets, hmac, time, argparse, sys
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import cv2
app=Flask(__name__)
app.secret_key=os.environ.get('SMART_LIBRARY_SECRET_KEY') or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=os.environ.get('SMART_LIBRARY_HTTPS')=='1', PERMANENT_SESSION_LIFETIME=datetime.timedelta(hours=8), MAX_CONTENT_LENGTH=10*1024*1024)

DB=os.path.join(os.path.dirname(__file__),'library.db')
BOOKS=[('1001','Абай жолы','Мұхтар Әуезов','abai.jpeg'),('1002','Көшпенділер','Ілияс Есенберлин','koshpendiler.jpeg'),('1003','Қан мен тер','Әбдіжәміл Нұрпейісов','kanmenter.jpeg'),('1004','Ақбілек','Жүсіпбек Аймауытов','akbilek.jpeg'),('1005','Ақан сері','Сәкен Жүнісов','akanseri.jpeg'),('1006','Ұшқан ұя','Бауыржан Момышұлы','ushkanuya.png'),('1007','Қара сөздер','Абай Құнанбайұлы','karasozder.png'),('1008','Бақытсыз Жамал','Міржақып Дулатұлы','jamal.png'),('1009','Шыңырау','Әбіш Кекілбаев','shynyrau.jpeg'),('1010','Мұхтар Әуезов. 47-том','Мұхтар Әуезов','auezov47.jpeg')]
def connect():
 c=sqlite3.connect(DB);c.row_factory=sqlite3.Row;return c
def init():
 with connect() as c:
  c.execute('CREATE TABLE IF NOT EXISTS books (code TEXT PRIMARY KEY,title TEXT,author TEXT,cover TEXT,available INTEGER DEFAULT 1, pdf_url TEXT DEFAULT "")')
  c.execute('CREATE TABLE IF NOT EXISTS loans (id INTEGER PRIMARY KEY AUTOINCREMENT,book_code TEXT,reader TEXT,issued_at TEXT,returned_at TEXT)')
  c.executemany('INSERT OR IGNORE INTO books(code,title,author,cover) VALUES (?,?,?,?)',BOOKS)
  columns = [row[1] for row in c.execute("PRAGMA table_info(books)")]
  if "total_copies" not in columns:
    c.execute("ALTER TABLE books ADD COLUMN total_copies INTEGER NOT NULL DEFAULT 1")
  loan_columns = [
            row[1] for row in
            c.execute("PRAGMA table_info(loans)")
        ]

  if "reader_type" not in loan_columns:
            c.execute(
                "ALTER TABLE loans ADD COLUMN reader_type TEXT"
            )

  c.execute("""
            CREATE TABLE IF NOT EXISTS book_copies (
                inventory_number TEXT PRIMARY KEY,
                book_code TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'available',
                FOREIGN KEY (book_code) REFERENCES books(code)
            )
        """)
  loan_cols = [row[1] for row in c.execute("PRAGMA table_info(loans)")]
  if 'inventory_number' not in loan_cols:
   c.execute('ALTER TABLE loans ADD COLUMN inventory_number TEXT')
init()

def auth_db_init():
 with connect() as c:
  c.execute('CREATE TABLE IF NOT EXISTS librarians (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL)')
  c.execute('CREATE TABLE IF NOT EXISTS login_attempts (address TEXT PRIMARY KEY, failures INTEGER NOT NULL, locked_until REAL NOT NULL)')
auth_db_init()

@app.before_request
def require_login():
 if request.endpoint in ('login','static'):
  return None
 if not session.get('librarian'):
  if request.path.startswith('/api/'):
   return jsonify(error='Кіру қажет'),401
  return redirect(url_for('login'))
 if request.method not in ('GET','HEAD','OPTIONS'):
  expected=session.get('csrf')
  supplied=request.headers.get('X-CSRF-Token','')
  if not expected or not hmac.compare_digest(expected,supplied):
   return jsonify(error='Қауіпсіздік тексеруі өтпеді. Бетті жаңартыңыз.'),403

@app.after_request
def secure_headers(response):
 response.headers['X-Content-Type-Options']='nosniff'
 response.headers['X-Frame-Options']='DENY'
 response.headers['Referrer-Policy']='same-origin'
 response.headers['Cache-Control']='no-store'
 response.headers['Content-Security-Policy']="default-src 'self' https://unpkg.com; script-src 'self' 'unsafe-inline' https://unpkg.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; media-src 'self' blob:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
 return response

@app.route('/login',methods=['GET','POST'])
def login():
 error=''
 with connect() as c:
  has_users=c.execute('SELECT 1 FROM librarians LIMIT 1').fetchone() is not None
 if request.method=='POST':
  username=request.form.get('username','').strip()
  password=request.form.get('password','')
  address=request.remote_addr or 'unknown'
  now=time.time()
  with connect() as c:
   state=c.execute('SELECT failures,locked_until FROM login_attempts WHERE address=?',(address,)).fetchone()
   if state and state['locked_until']>now:
    error='Көп әрекет жасалды. 15 минуттан кейін қайталаңыз.'
   else:
    row=c.execute('SELECT password_hash FROM librarians WHERE username=?',(username,)).fetchone()
    if row and check_password_hash(row['password_hash'],password):
     c.execute('DELETE FROM login_attempts WHERE address=?',(address,))
     session.clear();session.permanent=True
     session['librarian']=username;session['csrf']=secrets.token_urlsafe(32)
     return redirect(url_for('home'))
    failures=(state['failures'] if state else 0)+1
    c.execute('INSERT INTO login_attempts(address,failures,locked_until) VALUES(?,?,?) ON CONFLICT(address) DO UPDATE SET failures=excluded.failures,locked_until=excluded.locked_until',(address,failures,now+900 if failures>=5 else 0))
    error='Логин немесе құпиясөз дұрыс емес'
 return render_template('login.html',error=error,has_users=has_users)

@app.post('/logout')
def logout():
 session.clear()
 return redirect(url_for('login'))

@app.get('/api/auth')
def auth_state():
 return jsonify(username=session['librarian'],csrf=session['csrf'])

@app.get('/')
def home():return render_template('index.html',csrf_token=session['csrf'],librarian=session['librarian'])
@app.get('/api/books')
def books():
 with connect() as c:
  rows=[dict(x) for x in c.execute('SELECT * FROM books ORDER BY code')]
  copies=[dict(x) for x in c.execute('SELECT inventory_number,book_code,status FROM book_copies ORDER BY inventory_number')]
  active=c.execute('SELECT book_code,COUNT(*) AS n FROM loans WHERE returned_at IS NULL AND inventory_number IS NULL GROUP BY book_code').fetchall()
  legacy={x['book_code']:x['n'] for x in active}
  for b in rows:
   b['copies']=[x for x in copies if x['book_code']==b['code']]
   b['legacy_unassigned_loans']=legacy.get(b['code'],0)

  stats = {
            'total': len(rows),
            'total_copies': sum(x['total_copies'] for x in rows),
            'available': sum(x['available'] for x in rows),
            'loaned': sum(
                x['total_copies'] - x['available']
                for x in rows
            )
        }
 return jsonify(books=rows,stats=stats)
@app.get('/api/loans')
def loans():
 with connect() as c:return jsonify([dict(x) for x in c.execute('SELECT loans.*,books.title FROM loans JOIN books ON books.code=loans.book_code ORDER BY loans.id DESC LIMIT 100')])
@app.post('/api/transaction')
def transaction():
 d=request.get_json(silent=True) or {}
 code=str(d.get('code','')).strip()
 action=d.get('action')
 reader=str(d.get('reader','')).strip()
 reader_type=d.get('reader_type')
 with connect() as c:
  copy=c.execute('SELECT * FROM book_copies WHERE inventory_number=?',(code,)).fetchone()
  book_code=copy['book_code'] if copy else code
  b=c.execute('SELECT * FROM books WHERE code=?',(book_code,)).fetchone()
  if not b:return jsonify(error='Кітап немесе инвентарлық нөмір табылмады'),404
  if action=='issue':
   if reader_type not in ('student','teacher'):
    return jsonify(error='Оқырман түрін таңдаңыз'),400
   if not reader:return jsonify(error='Оқырманның аты қажет'),400
   if b['available']<=0:return jsonify(error='Кітап қолда жоқ'),409
   if copy:
    if copy['status']!='available':return jsonify(error='Бұл инвентарлық нөмірдегі кітап қолда жоқ'),409
    c.execute("UPDATE book_copies SET status='loaned' WHERE inventory_number=?",(code,))
   else:
    return jsonify(error='Кітапты тек инвентарлық нөмірмен беріңіз'),400
    # Legacy code-based loans remain possible, but cannot be assigned to an unknown inventory number.
    registered=c.execute('SELECT COUNT(*) FROM book_copies WHERE book_code=?',(book_code,)).fetchone()[0]
    legacy_active=c.execute('SELECT COUNT(*) FROM loans WHERE book_code=? AND returned_at IS NULL AND inventory_number IS NULL',(book_code,)).fetchone()[0]
    if b['total_copies']-registered-legacy_active<=0:
     return jsonify(error='Нақты дананың инвентарлық нөмірін енгізіңіз'),409
   c.execute('UPDATE books SET available=available-1 WHERE code=?',(book_code,))
   c.execute('INSERT INTO loans(book_code,reader,issued_at,reader_type,inventory_number) VALUES (?,?,?,?,?)',
             (book_code,reader,datetime.datetime.now().isoformat(timespec='seconds'),reader_type,code if copy else None))
  elif action=='return':
   if copy:
    loan=c.execute('SELECT id FROM loans WHERE inventory_number=? AND returned_at IS NULL ORDER BY id DESC LIMIT 1',(code,)).fetchone()
    if not loan:return jsonify(error='Бұл нөмірдегі кітап берілмеген'),409
   else:
    loan=c.execute('SELECT id FROM loans WHERE book_code=? AND inventory_number IS NULL AND returned_at IS NULL ORDER BY id DESC LIMIT 1',(book_code,)).fetchone()
    if not loan:return jsonify(error='Белсенді жазба табылмады. Инвентарлық нөмірді енгізіңіз'),409
   if b['available']>=b['total_copies']:return jsonify(error='Кітап қорының саны сәйкес келмейді'),409
   c.execute('UPDATE loans SET returned_at=? WHERE id=?',(datetime.datetime.now().isoformat(timespec='seconds'),loan['id']))
   c.execute('UPDATE books SET available=available+1 WHERE code=?',(book_code,))
   if copy:c.execute("UPDATE book_copies SET status='available' WHERE inventory_number=?",(code,))
  else:return jsonify(error='Белгісіз әрекет'),400
 return jsonify(ok=True)
@app.post('/api/scan-image')
def scan_image():
 f=request.files.get('image')
 if not f:return jsonify(error='Сурет берілмеді'),400
 import numpy as np
 raw=f.read()
 if len(raw)>8_000_000:return jsonify(error='Сурет тым үлкен'),413
 frame=cv2.imdecode(np.frombuffer(raw,dtype=np.uint8),cv2.IMREAD_COLOR)
 if frame is None:return jsonify(error='Суретті оқу мүмкін емес'),400
 detector=cv2.QRCodeDetector();text,_,_=detector.detectAndDecode(frame)
 if not text and hasattr(cv2,'barcode'):
  try:
   barcode=cv2.barcode.BarcodeDetector();ok,values,types,points=barcode.detectAndDecodeWithType(frame)
   if ok and values:text=values[0]
  except Exception:pass
 return jsonify(code=text or '',found=bool(text))
@app.post('/api/books/add')
def add_book():
    d = request.get_json(silent=True) or {}
    code = str(d.get('code', '')).strip()
    title = str(d.get('title', '')).strip()
    author = str(d.get('author', '')).strip()

    try:
        total = int(d.get('total_copies', 1))
    except (ValueError, TypeError):
        return jsonify(error='Кітап саны дұрыс емес'), 400

    if not code or not title or not author or total < 1:
        return jsonify(error='Мәліметтерді толық енгізіңіз'), 400

    with connect() as c:
        if c.execute('SELECT 1 FROM books WHERE code=?', (code,)).fetchone():
            return jsonify(error='Бұл кітап коды бұрын тіркелген'), 409

        c.execute(
            'INSERT INTO books (code,title,author,cover,available,total_copies) VALUES (?,?,?,?,?,?)',
            (code, title, author, '', total, total)
        )

    return jsonify(ok=True)
@app.post('/api/books/quantity')
def change_quantity():
    d = request.get_json(silent=True) or {}
    code = str(d.get('code', '')).strip()

    try:
        total = int(d.get('total_copies'))
    except (ValueError, TypeError):
        return jsonify(error='Кітап санын дұрыс енгізіңіз'), 400

    with connect() as c:
        book = c.execute(
            'SELECT * FROM books WHERE code=?', (code,)
        ).fetchone()

        if not book:
            return jsonify(error='Кітап табылмады'), 404

        borrowed = book['total_copies'] - book['available']

        if total < borrowed or total < 1:
            return jsonify(error='Саны берілген кітаптардан аз болмауы керек'), 400

        c.execute(
            'UPDATE books SET total_copies=?, available=? WHERE code=?',
            (total, total - borrowed, code)
        )

    return jsonify(ok=True)
@app.post('/api/books/edit')
def edit_book():
    d = request.get_json(silent=True) or {}
    old_code = str(d.get('old_code', '')).strip()
    new_code = str(d.get('new_code', '')).strip()
    title = str(d.get('title', '')).strip()
    author = str(d.get('author', '')).strip()

    try:
        total = int(d.get('total_copies'))
    except (ValueError, TypeError):
        return jsonify(error='Дана санын дұрыс енгізіңіз'), 400

    if not all([old_code, new_code, title, author]) or total < 1:
        return jsonify(error='Барлық мәліметті толтырыңыз'), 400

    with connect() as c:
        book = c.execute(
            'SELECT * FROM books WHERE code=?',
            (old_code,)
        ).fetchone()

        if not book:
            return jsonify(error='Кітап табылмады'), 404

        if old_code != new_code:
            exists = c.execute(
                'SELECT 1 FROM books WHERE code=?',
                (new_code,)
            ).fetchone()
            if exists:
                return jsonify(error='Жаңа код бұрын тіркелген'), 409

        borrowed = c.execute(
            '''SELECT COUNT(*) FROM loans
               WHERE book_code=? AND returned_at IS NULL''',
            (old_code,)
        ).fetchone()[0]

        registered=c.execute('SELECT COUNT(*) FROM book_copies WHERE book_code=?',(old_code,)).fetchone()[0]
        unassigned=c.execute('SELECT COUNT(*) FROM loans WHERE book_code=? AND returned_at IS NULL AND inventory_number IS NULL',(old_code,)).fetchone()[0]
        if total < max(borrowed,registered+unassigned):
            return jsonify(
                error='Жалпы саны тіркелген немесе берілген даналардан аз'
            ), 400

        c.execute(
            '''UPDATE books
               SET code=?, title=?, author=?,
                   total_copies=?, available=?
               WHERE code=?''',
            (new_code, title, author,
             total, total - borrowed, old_code)
        )

        if old_code != new_code:
            c.execute('UPDATE book_copies SET book_code=? WHERE book_code=?',(new_code,old_code))
            c.execute(
                'UPDATE loans SET book_code=? WHERE book_code=?',
                (new_code, old_code)
            )

    return jsonify(ok=True)

@app.delete('/api/books/<code>')
def delete_book(code):
    with connect() as c:
        book = c.execute(
            'SELECT code FROM books WHERE code=?',
            (code,)
        ).fetchone()

        if not book:
            return jsonify(
                error='Кітап табылмады'
            ), 404

        history = c.execute(
            'SELECT COUNT(*) FROM loans WHERE book_code=?',
            (code,)
        ).fetchone()[0]

        copies_count=c.execute('SELECT COUNT(*) FROM book_copies WHERE book_code=?',(code,)).fetchone()[0]
        if copies_count:
            return jsonify(error='Алдымен осы кітаптың инвентарлық даналарын реттеңіз'),409
        if history > 0:
            return jsonify(
                error='Бұл кітаптың беру-қайтару тарихы бар. Жоюға болмайды.'
            ), 409

        registered=c.execute('SELECT COUNT(*) FROM book_copies WHERE book_code=?',(code,)).fetchone()[0]
        if registered:
            return jsonify(error='Алдымен тіркелген инвентарлық нөмірлерді тексеріңіз. Кітапты жоюға болмайды.'),409
        c.execute(
            'DELETE FROM books WHERE code=?',
            (code,)
        )

    return jsonify(ok=True)

# Add the following routes to app.py immediately BEFORE the final
# if __name__ == '__main__': app.run(...) line.
# Existing database schema and records remain unchanged.

@app.get('/api/loans/active')
def active_loans_search():
    reader = request.args.get('reader', '').strip()
    if not reader:
        return jsonify([])
    with connect() as c:
        rows = c.execute('''SELECT loans.id, loans.reader, loans.reader_type,
                                    loans.issued_at, loans.book_code, books.title
                             FROM loans JOIN books ON books.code=loans.book_code
                             WHERE loans.returned_at IS NULL
                               AND LOWER(loans.reader) LIKE LOWER(?)
                             ORDER BY loans.issued_at DESC, loans.id DESC
                             LIMIT 100''', ('%' + reader + '%',)).fetchall()
    return jsonify([dict(row) for row in rows])

@app.post('/api/loans/<int:loan_id>/return')
def return_specific_loan(loan_id):
    with connect() as c:
        loan = c.execute('''SELECT loans.id, loans.book_code, books.available, books.total_copies
                            FROM loans JOIN books ON books.code=loans.book_code
                            WHERE loans.id=? AND loans.returned_at IS NULL''', (loan_id,)).fetchone()
        if loan is None:
            return jsonify(error='Кітап бұрын қайтарылған немесе жазба табылмады'), 404
        if loan['available'] >= loan['total_copies']:
            return jsonify(error='Кітап қорының саны сәйкес келмейді'), 409
        now = datetime.datetime.now().isoformat(timespec='seconds')
        c.execute('UPDATE loans SET returned_at=? WHERE id=? AND returned_at IS NULL',
                  (now, loan_id))
        c.execute('UPDATE books SET available=available+1 WHERE code=?',
                  (loan['book_code'],))
        inv=c.execute('SELECT inventory_number FROM loans WHERE id=?',(loan_id,)).fetchone()['inventory_number']
        if inv:c.execute("UPDATE book_copies SET status='available' WHERE inventory_number=?",(inv,))
        inv = c.execute('SELECT inventory_number FROM loans WHERE id=?',(loan_id,)).fetchone()['inventory_number']
        if inv:
            c.execute("UPDATE book_copies SET status='available' WHERE inventory_number=?",(inv,))
    return jsonify(ok=True)

# SMART LIBRARY AI - statistics routes
# Paste BEFORE: if __name__ == '__main__':
from flask import Response
import csv
import io
import calendar


def _report_period():
    today = datetime.date.today()
    try:
        year = int(request.args.get('year', today.year))
        month = int(request.args.get('month', today.month))
        school_year = int(request.args.get('school_year', request.args.get('year', today.year if today.month >= 9 else today.year - 1)))
        mode = request.args.get('period', 'month')
        if mode not in ('month', 'school_year') or not (2000 <= year <= 2100 and 1 <= month <= 12 and 2000 <= school_year <= 2100):
            raise ValueError()
    except (ValueError, TypeError):
        return None
    if mode == 'month':
        start = datetime.date(year, month, 1)
        end = datetime.date(year + (month == 12), month % 12 + 1, 1)
        label = f'{year}-{month:02d}'
    else:
        start = datetime.date(school_year, 9, 1)
        end = datetime.date(school_year + 1, 9, 1)
        label = f'{school_year}-{school_year + 1}'
    return start.isoformat(), end.isoformat(), label, mode


def _report_data(start, end):
    result = {}
    with connect() as c:
        for reader_type, label in (('student', 'Оқушылар'), ('teacher', 'Мұғалімдер')):
            # One distinct normalized full name counts as one reader per period.
            issued = c.execute('''SELECT COUNT(*) FROM loans
                WHERE reader_type=? AND issued_at>=? AND issued_at<?''',
                (reader_type, start, end)).fetchone()[0]
            readers = c.execute('''SELECT COUNT(DISTINCT LOWER(TRIM(reader))) FROM loans
                WHERE reader_type=? AND issued_at>=? AND issued_at<?
                AND TRIM(reader)<>'' ''', (reader_type, start, end)).fetchone()[0]
            returned = c.execute('''SELECT COUNT(*) FROM loans
                WHERE reader_type=? AND returned_at>=? AND returned_at<?''',
                (reader_type, start, end)).fetchone()[0]
            outstanding = c.execute('''SELECT COUNT(*) FROM loans
                WHERE reader_type=? AND returned_at IS NULL''',
                (reader_type,)).fetchone()[0]
            result[reader_type] = dict(label=label, readers=readers,
                issued=issued, returned=returned, outstanding_now=outstanding)
    return result


@app.get('/api/statistics')
def library_statistics():
    period = _report_period()
    if period is None:
        return jsonify(error='Ай немесе жыл дұрыс көрсетілмеген'), 400
    start, end, label, mode = period
    return jsonify(period=mode, label=label, start=start, end_exclusive=end,
                   groups=_report_data(start, end),
                   note='Қайтарылмаған саны - қазіргі уақыттағы қалдық; басқа көрсеткіштер таңдалған кезең бойынша.')


@app.get('/api/statistics/export')
def library_statistics_export():
    period = _report_period()
    if period is None:
        return jsonify(error='Ай немесе жыл дұрыс көрсетілмеген'), 400
    start, end, label, mode = period
    groups = _report_data(start, end)
    output = io.StringIO()
    writer = csv.writer(output, delimiter=';')
    writer.writerow(['Кезең', 'Топ', 'Бірегей оқырман', 'Берілген кітап',
                     'Кезеңде қайтарылған', 'Қазір қайтарылмаған'])
    for group in groups.values():
        writer.writerow([label, group['label'], group['readers'], group['issued'],
                         group['returned'], group['outstanding_now']])
    data = '\ufeff' + output.getvalue()  # UTF-8 BOM for Excel
    return Response(data, mimetype='text/csv; charset=utf-8', headers={
        'Content-Disposition': f'attachment; filename="library_report_{label}.csv"'})

@app.get('/api/loans/search-by-book')
def search_loans_by_book():
    title = request.args.get('title', '').strip()

    if not title:
        return jsonify([])

    with connect() as c:
        rows = c.execute("""
            SELECT
                loans.id,
                loans.reader,
                loans.reader_type,
                loans.issued_at,
                loans.book_code,
                books.title,
                books.author
            FROM loans
            JOIN books
              ON books.code = loans.book_code
            WHERE loans.returned_at IS NULL
              AND LOWER(books.title) LIKE LOWER(?)
            ORDER BY loans.issued_at DESC
            LIMIT 100
        """, ('%' + title + '%',)).fetchall()

    return jsonify([dict(row) for row in rows])

@app.get('/api/loans/search-by-author')
def search_loans_by_author():
    author = request.args.get('author', '').strip()

    if not author:
        return jsonify([])

    with connect() as c:
        rows = c.execute("""
            SELECT
                loans.id,
                loans.reader,
                loans.reader_type,
                loans.issued_at,
                loans.book_code,
                books.title,
                books.author
            FROM loans
            JOIN books
              ON books.code = loans.book_code
            WHERE loans.returned_at IS NULL
              AND LOWER(books.author) LIKE LOWER(?)
            ORDER BY loans.issued_at DESC
            LIMIT 100
        """, ('%' + author + '%',)).fetchall()

    return jsonify([dict(row) for row in rows])
@app.post('/api/copies/add')
def add_book_copy():
    d = request.get_json(silent=True) or {}
    book_code = str(d.get('book_code', '')).strip()
    inventory = str(d.get('inventory_number', '')).strip()

    if not book_code or not inventory:
        return jsonify(
            error='Кітап пен инвентарлық нөмір қажет'
        ), 400

    with connect() as c:
        book = c.execute(
            'SELECT code FROM books WHERE code=?',
            (book_code,)
        ).fetchone()

        if not book:
            return jsonify(error='Кітап табылмады'), 404

        existing = c.execute(
            'SELECT 1 FROM book_copies WHERE inventory_number=?',
            (inventory,)
        ).fetchone()

        if existing:
            return jsonify(
                error='Бұл инвентарлық нөмір тіркелген'
            ), 409

        c.execute("INSERT INTO book_copies (inventory_number, book_code, status) VALUES (?, ?, 'available')", (inventory, book_code))
        count = c.execute('SELECT COUNT(*) FROM book_copies WHERE book_code=?', (book_code,)).fetchone()[0]
        legacy = c.execute('SELECT COUNT(*) FROM loans WHERE book_code=? AND returned_at IS NULL AND inventory_number IS NULL', (book_code,)).fetchone()[0]
        total = max(book['total_copies'], count + legacy)
        active = c.execute('SELECT COUNT(*) FROM loans WHERE book_code=? AND returned_at IS NULL', (book_code,)).fetchone()[0]
        c.execute('UPDATE books SET total_copies=?, available=? WHERE code=?', (total, max(0,total-active),book_code))

    return jsonify(ok=True)
@app.post('/api/inventory/register')
def register_inventory():
    d=request.get_json(silent=True) or {}
    inventory=str(d.get('inventory_number','')).strip()
    title=str(d.get('title','')).strip()
    author=str(d.get('author','')).strip()
    code=str(d.get('book_code','')).strip()
    if not inventory or (not code and (not title or not author)):
        return jsonify(error='Кітапты және инвентарлық нөмірді толтырыңыз'),400
    with connect() as c:
        if c.execute('SELECT 1 FROM book_copies WHERE inventory_number=?',(inventory,)).fetchone():
            return jsonify(error='Бұл инвентарлық нөмір тіркелген'),409
        if code:
            book=c.execute('SELECT * FROM books WHERE code=?',(code,)).fetchone()
            if not book:return jsonify(error='Кітап табылмады'),404
        else:
            book=c.execute('SELECT * FROM books WHERE LOWER(TRIM(title))=LOWER(?) AND LOWER(TRIM(author))=LOWER(?)',(title,author)).fetchone()
            if book:
                code=book['code']
            else:
                codes=[int(x[0]) for x in c.execute('SELECT code FROM books') if x[0].isdigit()]
                code=str(max([1000]+codes)+1)
                c.execute('INSERT INTO books(code,title,author,cover,available,total_copies) VALUES (?,?,?,?,0,0)',(code,title,author,''))
                book=c.execute('SELECT * FROM books WHERE code=?',(code,)).fetchone()
        c.execute("INSERT INTO book_copies(inventory_number,book_code,status) VALUES (?,?,'available')",(inventory,code))
        registered=c.execute('SELECT COUNT(*) FROM book_copies WHERE book_code=?',(code,)).fetchone()[0]
        legacy=c.execute('SELECT COUNT(*) FROM loans WHERE book_code=? AND returned_at IS NULL AND inventory_number IS NULL',(code,)).fetchone()[0]
        total=max(book['total_copies'],registered+legacy)
        active=c.execute('SELECT COUNT(*) FROM loans WHERE book_code=? AND returned_at IS NULL',(code,)).fetchone()[0]
        c.execute('UPDATE books SET total_copies=?,available=? WHERE code=?',(total,max(0,total-active),code))
    return jsonify(ok=True,book_code=code)


@app.post('/api/inventory/rename')
def rename_inventory():
    d=request.get_json(silent=True) or {}
    old=str(d.get('old_number','')).strip()
    new=str(d.get('new_number','')).strip()
    if not old or not new:
        return jsonify(error='Ескі және жаңа нөмір қажет'),400
    with connect() as c:
        copy=c.execute('SELECT book_code,status FROM book_copies WHERE inventory_number=?',(old,)).fetchone()
        if not copy:return jsonify(error='Инвентарлық нөмір табылмады'),404
        if old!=new and c.execute('SELECT 1 FROM book_copies WHERE inventory_number=?',(new,)).fetchone():
            return jsonify(error='Бұл нөмір басқа кітапта бар'),409
        if old!=new:
            c.execute('UPDATE book_copies SET inventory_number=? WHERE inventory_number=?',(new,old))
            c.execute('UPDATE loans SET inventory_number=? WHERE inventory_number=?',(new,old))
    return jsonify(ok=True)

@app.post('/api/catalog/edit')
def edit_catalog():
    d=request.get_json(silent=True) or {}
    code=str(d.get('book_code','')).strip()
    title=str(d.get('title','')).strip()
    author=str(d.get('author','')).strip()
    if not code or not title or not author:return jsonify(error='Барлық мәліметті толтырыңыз'),400
    with connect() as c:
        if not c.execute('SELECT 1 FROM books WHERE code=?',(code,)).fetchone():
            return jsonify(error='Кітап табылмады'),404
        duplicate=c.execute('SELECT 1 FROM books WHERE code<>? AND LOWER(TRIM(title))=LOWER(?) AND LOWER(TRIM(author))=LOWER(?)',(code,title,author)).fetchone()
        if duplicate:return jsonify(error='Осындай кітап бұрын тіркелген'),409
        c.execute('UPDATE books SET title=?,author=? WHERE code=?',(title,author,code))
    return jsonify(ok=True)
if __name__=='__main__':
 parser=argparse.ArgumentParser()
 parser.add_argument('--set-admin',action='store_true',help='Set or reset librarian credentials')
 parser.add_argument('--host',default=os.environ.get('SMART_LIBRARY_HOST','127.0.0.1'))
 parser.add_argument('--port',type=int,default=int(os.environ.get('PORT','5000')))
 args=parser.parse_args()
 if args.set_admin:
  import getpass
  username=input('Login: ').strip()
  password=getpass.getpass('Password (12+ characters): ')
  confirm=getpass.getpass('Repeat password: ')
  if not username or len(password)<12 or password!=confirm:
   print('ERROR: username required, password >=12 characters and matching confirmation');sys.exit(1)
  with connect() as c:
   c.execute('INSERT INTO librarians(username,password_hash) VALUES (?,?) ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash',(username,generate_password_hash(password)))
  print('Account saved.')
 else:
  with connect() as c:
   exists=c.execute('SELECT 1 FROM librarians LIMIT 1').fetchone()
  if not exists:
   print('SETUP REQUIRED: run python app.py --set-admin');sys.exit(1)
  app.run(debug=False,host=args.host,port=args.port)

