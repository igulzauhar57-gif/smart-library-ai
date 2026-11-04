from flask import Flask, render_template, request, jsonify
import sqlite3, os, datetime
import cv2
app=Flask(__name__)
DB=os.path.join(os.path.dirname(__file__),'library.db')
BOOKS=[('1001','Абай жолы','Мұхтар Әуезов','abai.jpeg'),('1002','Көшпенділер','Ілияс Есенберлин','koshpendiler.jpeg'),('1003','Қан мен тер','Әбдіжәміл Нұрпейісов','kanmenter.jpeg'),('1004','Ақбілек','Жүсіпбек Аймауытов','akbilek.jpeg'),('1005','Ақан сері','Сәкен Жүнісов','akanseri.jpeg'),('1006','Ұшқан ұя','Бауыржан Момышұлы','ushkanuya.png'),('1007','Қара сөздер','Абай Құнанбайұлы','karasozder.png'),('1008','Бақытсыз Жамал','Міржақып Дулатұлы','jamal.png'),('1009','Шыңырау','Әбіш Кекілбаев','shynyrau.jpeg'),('1010','Мұхтар Әуезов. 47-том','Мұхтар Әуезов','auezov47.jpeg')]
def connect():
 c=sqlite3.connect(DB);c.row_factory=sqlite3.Row;return c
def init():
 with connect() as c:
  c.execute('CREATE TABLE IF NOT EXISTS books (code TEXT PRIMARY KEY,title TEXT,author TEXT,cover TEXT,available INTEGER DEFAULT 1, pdf_url TEXT DEFAULT "")')
  c.execute('CREATE TABLE IF NOT EXISTS loans (id INTEGER PRIMARY KEY AUTOINCREMENT,book_code TEXT,reader TEXT,issued_at TEXT,returned_at TEXT)')
  c.executemany('INSERT OR IGNORE INTO books(code,title,author,cover) VALUES (?,?,?,?)',BOOKS)
init()
@app.get('/')
def home():return render_template('index.html')
@app.get('/api/books')
def books():
 with connect() as c:
  rows=[dict(x) for x in c.execute('SELECT * FROM books ORDER BY code')]
  stats={'total':len(rows),'available':sum(x['available'] for x in rows),'loaned':sum(not x['available'] for x in rows)}
 return jsonify(books=rows,stats=stats)
@app.get('/api/loans')
def loans():
 with connect() as c:return jsonify([dict(x) for x in c.execute('SELECT loans.*,books.title FROM loans JOIN books ON books.code=loans.book_code ORDER BY loans.id DESC LIMIT 100')])
@app.post('/api/transaction')
def transaction():
 d=request.get_json(silent=True) or {};code=str(d.get('code','')).strip();action=d.get('action');reader=str(d.get('reader','')).strip()
 with connect() as c:
  b=c.execute('SELECT * FROM books WHERE code=?',(code,)).fetchone()
  if not b:return jsonify(error='Кітап коды табылмады'),404
  if action=='issue':
   if not reader:return jsonify(error='Оқырманның аты қажет'),400
   if not b['available']:return jsonify(error='Кітап беріліп қойған'),409
   c.execute('UPDATE books SET available=0 WHERE code=?',(code,))
   c.execute('INSERT INTO loans(book_code,reader,issued_at) VALUES (?,?,?)',(code,reader,datetime.datetime.now().isoformat(timespec='seconds')))
  elif action=='return':
   if b['available']:return jsonify(error='Кітап кітапханада тұр'),409
   loan=c.execute('SELECT id FROM loans WHERE book_code=? AND returned_at IS NULL ORDER BY id DESC LIMIT 1',(code,)).fetchone()
   if not loan:return jsonify(error='Белсенді жазба табылмады'),409
   c.execute('UPDATE loans SET returned_at=? WHERE id=?',(datetime.datetime.now().isoformat(timespec='seconds'),loan['id']))
   c.execute('UPDATE books SET available=1 WHERE code=?',(code,))
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
if __name__=='__main__':app.run(debug=True,host='127.0.0.1',port=5000)
