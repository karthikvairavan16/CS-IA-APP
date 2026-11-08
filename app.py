"""IA Project: Python Gmail prioritizer. Run locally or on a single Railway service."""
import argparse
import base64
from contextlib import contextmanager
import ctypes
import datetime as dt
import email.utils
from email.message import EmailMessage
import hashlib
import hmac
import html
from html.parser import HTMLParser
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import threading
import time
import unicodedata
from urllib import error, parse, request

from views import PAGE

ROOT = Path(__file__).resolve().parent
HOSTED = bool(os.environ.get('RAILWAY_SERVICE_ID'))
DATA = Path(os.environ.get('DATA_DIR') or os.environ.get('RAILWAY_VOLUME_MOUNT_PATH') or ROOT / 'private_data')
DB = DATA / 'staffroom.db'
CONFIG = DATA / 'google.json'
ORIGIN = (os.environ.get('APP_ORIGIN') or
          ('https://' + os.environ['RAILWAY_PUBLIC_DOMAIN'] if os.environ.get('RAILWAY_PUBLIC_DOMAIN') else
           'http://localhost:8000')).rstrip('/')
REDIRECT = ORIGIN + '/auth/callback'
HOST = parse.urlsplit(ORIGIN).netloc
PORT = int(os.environ.get('PORT', '8000'))
SCOPE = 'openid email profile https://www.googleapis.com/auth/gmail.modify'
GMAIL = 'https://gmail.googleapis.com/gmail/v1/users/me'
SYNC_LOCK = threading.Lock()


class AppError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


@contextmanager
def connect():
    con = sqlite3.connect(DB, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA foreign_keys=ON')
    try:
        with con:
            yield con
    finally:
        con.close()


def init_db():
    DATA.mkdir(exist_ok=True)
    with connect() as con:
        con.executescript('''
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY, sub TEXT UNIQUE NOT NULL, email TEXT NOT NULL,
          name TEXT NOT NULL, username TEXT UNIQUE COLLATE NOCASE, password TEXT,
          avatar TEXT DEFAULT '', tokens TEXT, history TEXT DEFAULT '',
          last_sync REAL DEFAULT 0, theme TEXT DEFAULT 'light');
        CREATE TABLE IF NOT EXISTS sessions(
          token TEXT PRIMARY KEY, uid INTEGER REFERENCES users(id) ON DELETE CASCADE,
          csrf TEXT NOT NULL, expires REAL NOT NULL, state TEXT, verifier TEXT,
          oauth_time REAL, mode TEXT, reconnect INTEGER DEFAULT 0, verified REAL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS messages(
          uid INTEGER REFERENCES users(id) ON DELETE CASCADE, id TEXT,
          subject TEXT, sender TEXT, sender_email TEXT, body TEXT, received TEXT,
          labels TEXT, PRIMARY KEY(uid,id));
        CREATE TABLE IF NOT EXISTS rules(
          id INTEGER PRIMARY KEY, uid INTEGER REFERENCES users(id) ON DELETE CASCADE,
          field TEXT NOT NULL, term TEXT NOT NULL, points INTEGER NOT NULL,
          label TEXT DEFAULT '', notify INTEGER DEFAULT 0, enabled INTEGER DEFAULT 1);
        CREATE TABLE IF NOT EXISTS notices(
          id INTEGER PRIMARY KEY, uid INTEGER REFERENCES users(id) ON DELETE CASCADE,
          mid TEXT NOT NULL, title TEXT NOT NULL, created REAL NOT NULL,
          seen INTEGER DEFAULT 0, UNIQUE(uid,mid));
        CREATE TABLE IF NOT EXISTS bulk_plans(
          token TEXT PRIMARY KEY, uid INTEGER REFERENCES users(id) ON DELETE CASCADE,
          ids TEXT NOT NULL, expires REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS blocked_senders(
          uid INTEGER REFERENCES users(id) ON DELETE CASCADE, sender TEXT,
          filter_id TEXT NOT NULL, PRIMARY KEY(uid,sender));
        CREATE TABLE IF NOT EXISTS attempts(key TEXT PRIMARY KEY, count INTEGER, started REAL);
        ''')


def protect(text, decrypt=False):
    """Use a stable Fernet key in hosting; retain Windows DPAPI for local data."""
    master_key = os.environ.get('TOKEN_ENCRYPTION_KEY')
    if master_key:
        try:
            from cryptography.fernet import Fernet, InvalidToken
            cipher = Fernet(master_key.encode())
            return (cipher.decrypt(text.encode()).decode() if decrypt else
                    cipher.encrypt(text.encode()).decode())
        except (ValueError, InvalidToken):
            raise AppError('The token encryption key is invalid or has changed. Restore the original key.', 503) from None
    if os.name != 'nt':
        raise AppError('Set TOKEN_ENCRYPTION_KEY to enable encrypted Google credentials on this server.', 503)
    from ctypes import wintypes

    class Blob(ctypes.Structure):
        _fields_ = [('size', wintypes.DWORD), ('data', ctypes.POINTER(ctypes.c_ubyte))]

    raw = base64.b64decode(text) if decrypt else text.encode()
    buf = ctypes.create_string_buffer(raw)
    source = Blob(len(raw), ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte)))
    result = Blob()
    crypt = ctypes.WinDLL('crypt32', use_last_error=True)
    fn = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
    fn.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p,
                   ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
    fn.restype = wintypes.BOOL
    if not fn(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(result)):
        code = ctypes.get_last_error()
        raise AppError('Windows credential encryption failed (error %s). Run the app in a normal terminal under your Windows account; reconnect Google if necessary.' % code, 503)
    try:
        output = ctypes.string_at(result.data, result.size)
        return output.decode() if decrypt else base64.b64encode(output).decode()
    finally:
        ctypes.windll.kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        ctypes.windll.kernel32.LocalFree(ctypes.cast(result.data, ctypes.c_void_p))


def google_config():
    if os.environ.get('GOOGLE_CLIENT_ID') and os.environ.get('GOOGLE_CLIENT_SECRET'):
        return {'client_id': os.environ['GOOGLE_CLIENT_ID'],
                'client_secret': os.environ['GOOGLE_CLIENT_SECRET']}
    if not CONFIG.exists():
        raise AppError('Google is not configured yet. In your terminal run: python app.py --configure', 503)
    return json.loads(protect(CONFIG.read_text(), True))


def google_is_configured():
    return bool((os.environ.get('GOOGLE_CLIENT_ID') and os.environ.get('GOOGLE_CLIENT_SECRET')) or CONFIG.exists())


def http_json(url, method='GET', payload=None, token=None, form=False):
    headers = {'Accept': 'application/json'}
    data = None
    if payload is not None:
        data = (parse.urlencode(payload) if form else json.dumps(payload)).encode()
        headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
    if token:
        headers['Authorization'] = 'Bearer ' + token
    req = request.Request(url, data=data, headers=headers, method=method)
    try:
        with request.urlopen(req, timeout=25) as response:
            raw = response.read()
            return json.loads(raw) if raw else {}
    except error.HTTPError as exc:
        # Never expose OAuth responses/tokens to the browser or logs.
        if exc.code == 404:
            raise AppError('Google item not found; try refreshing.', 404) from None
        if exc.code == 400 and 'oauth2.googleapis.com/revoke' in url:
            raise AppError('Google access was already revoked.', 400) from None
        if exc.code in (401, 400) and 'oauth2.googleapis.com/token' in url:
            raise AppError('Google authorization expired or was revoked. Reconnect Google in Settings.', 401) from None
        if exc.code == 403:
            raise AppError('Google denied access. Check Gmail API, consent permissions, and school admin restrictions.', 403) from None
        if exc.code == 429:
            raise AppError('Google rate limit reached. Wait a minute before refreshing.', 429) from None
        raise AppError('Google request failed (HTTP %s). Reconnect or try again.' % exc.code, 502) from None
    except (error.URLError, TimeoutError, OSError):
        raise AppError('Cannot reach Google. Check your internet connection and try again.', 502) from None


def save_tokens(uid, tokens):
    with connect() as con:
        con.execute('UPDATE users SET tokens=? WHERE id=?', (protect(json.dumps(tokens)), uid))


def access_token(uid):
    with connect() as con:
        user = con.execute('SELECT tokens FROM users WHERE id=?', (uid,)).fetchone()
    if not user or not user['tokens']:
        raise AppError('Connect Google in Settings to synchronize Gmail.', 401)
    tokens = json.loads(protect(user['tokens'], True))
    if tokens.get('expires_at', 0) < time.time() + 90:
        if not tokens.get('refresh_token'):
            raise AppError('Reconnect Google to allow background access.', 401)
        cfg = google_config()
        fresh = http_json('https://oauth2.googleapis.com/token', 'POST', {
            'grant_type': 'refresh_token', 'refresh_token': tokens['refresh_token'],
            'client_id': cfg['client_id'], 'client_secret': cfg['client_secret']}, form=True)
        tokens.update(fresh)
        tokens['expires_at'] = time.time() + fresh.get('expires_in', 3600)
        save_tokens(uid, tokens)
    return tokens['access_token']


def gmail(token, path, method='GET', payload=None, **params):
    return http_json(GMAIL + path + ('?' + parse.urlencode(params, doseq=True) if params else ''), method, payload, token)


def blocked_sender_list(uid):
    """Keep saved entries visible when live verification is unavailable."""
    with connect() as con:
        saved = [dict(r) for r in con.execute('SELECT sender,filter_id FROM blocked_senders WHERE uid=? ORDER BY sender', (uid,))]
        user = con.execute('SELECT tokens FROM users WHERE id=?', (uid,)).fetchone()
    entries = [dict(r, managed=True, status='Not verified') for r in saved]
    warning = ''
    can_manage = False
    try:
        if not user['tokens']:
            raise AppError('Reconnect Google to verify your saved sender filters.')
        tokens = json.loads(protect(user['tokens'], True))
        can_manage = 'https://www.googleapis.com/auth/gmail.settings.basic' in tokens.get('scope', '').split()
        if not can_manage:
            raise AppError('Gmail filter permission is missing. Enable filter access below to check or change blocks.')
        filters = gmail(access_token(uid), '/settings/filters').get('filter', [])
        live = {f['id']: f for f in filters}
        for entry in entries:
            current = live.get(entry['filter_id'], {})
            entry['status'] = ('Active' if current.get('criteria') == {'from': entry['sender']} and
                               'TRASH' in current.get('action', {}).get('addLabelIds', []) else 'Not active in Gmail')
        known = {r['filter_id'] for r in saved}
        for item in filters:
            criteria = item.get('criteria', {})
            sender = criteria.get('from', '')
            if (item['id'] not in known and set(criteria) == {'from'} and
                    re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', sender) and
                    'TRASH' in item.get('action', {}).get('addLabelIds', [])):
                entries.append({'sender': sender, 'filter_id': item['id'], 'managed': False, 'status': 'Active'})
    except AppError as exc:
        warning = str(exc)
    entries.sort(key=lambda entry: entry['sender'].casefold())
    return {'senders': [r['sender'] for r in entries], 'entries': entries,
            'warning': warning, 'can_manage': can_manage}


class PlainHTML(HTMLParser):
    def __init__(self):
        super().__init__()
        self.bits = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'):
            self.hidden += 1
        if tag in ('p', 'div', 'br', 'li', 'tr') and not self.hidden:
            self.bits.append('\n')

    def handle_endtag(self, tag):
        if tag in ('script', 'style'):
            self.hidden = max(0, self.hidden - 1)

    def handle_data(self, data):
        if not self.hidden:
            self.bits.append(data)


def message_body(payload):
    def collect(part):
        if part.get('filename'):
            return [], []  # Attachments are deliberately not downloaded.
        plain, rich = [], []
        raw = part.get('body', {}).get('data')
        if raw:
            decoded = base64.urlsafe_b64decode(raw + '=' * (-len(raw) % 4)).decode('utf-8', errors='replace')
            if part.get('mimeType') == 'text/plain':
                plain.append(decoded)
            elif part.get('mimeType') == 'text/html':
                reader = PlainHTML()
                reader.feed(decoded)
                rich.append(''.join(reader.bits))
        for child in part.get('parts', []):
            p, r = collect(child)
            plain.extend(p)
            rich.extend(r)
        return plain, rich
    plain, rich = collect(payload)
    return re.sub(r'\n{3,}', '\n\n', '\n'.join(plain or rich)).strip()


def normalize_message(data):
    headers = {h['name'].lower(): h['value'] for h in data['payload'].get('headers', [])}
    name, address = email.utils.parseaddr(headers.get('from', ''))
    received = dt.datetime.fromtimestamp(int(data.get('internalDate', 0)) / 1000, dt.timezone.utc).isoformat()
    return {'id': data['id'], 'subject': headers.get('subject', '(No subject)'),
            'sender': name or address, 'sender_email': address, 'received': received,
            'body': message_body(data['payload']) or html.unescape(data.get('snippet', '')),
            'labels': data.get('labelIds', [])}


# Each category contributes once, even if its words repeat.
CATEGORIES = [
    ('Safety concern', 35, r'\b(safety hazard|safeguarding|lockdown|evacuat\w*|medical emergency|fire(?!\s+drill)|weapon|immediate danger)\b'),
    ('Student wellbeing', 20, r'\b(student concern\w*|student welfare|bully\w*|wellbeing|well-being|student at risk|child protection)\b'),
    ('Urgent action', 18, r'\b(urgent|immediately|asap|action required|overdue|past due)\b'),
    ('Assessment', 10, r'\b(exam\w*|midterm\w*|assessment\w*|examination\w*|report cards?|predicted grades?)\b'),
    ('Planned safety drill', 10, r'\b(fire drill|safety drill|evacuation drill)\b'),
]
DEADLINE_WORDS = r'\b(deadline|due|submit|submission|by|exam\w*|midterm\w*|drill|meeting|tomorrow|today)\b'
MONTHS = {name.lower(): i for i in range(1, 13) for name in (dt.date(2000, i, 1).strftime('%B'), dt.date(2000, i, 1).strftime('%b'))}


def extract_deadlines(text, received):
    """Conservative dates from action sentences; relative dates anchor to send date."""
    candidates = []
    for sentence in re.split(r'[\n.!?]+', text):
        if not re.search(DEADLINE_WORDS, sentence, re.I):
            continue
        lower = sentence.lower()
        for days in re.findall(r'\bin\s+(\d{1,3})\s+days?\b', lower):
            candidates.append(received + dt.timedelta(days=int(days)))
        if re.search(r'\btomorrow\b', lower):
            candidates.append(received + dt.timedelta(days=1))
        if re.search(r'\btoday\b', lower):
            candidates.append(received)
        if re.search(r'\bnext week\b', lower):
            candidates.append(received + dt.timedelta(days=7))
        for year, month, day in re.findall(r'\b(20\d{2})-(\d{1,2})-(\d{1,2})\b', lower):
            try:
                candidates.append(dt.date(int(year), int(month), int(day)))
            except ValueError:
                pass
        month_pattern = '|'.join(MONTHS)
        for match in re.finditer(r'\b(?:(\d{1,2})(?:st|nd|rd|th)?\s+(' + month_pattern + r')|(' + month_pattern + r')\s+(\d{1,2})(?:st|nd|rd|th)?)(?:,?\s+(20\d{2}))?\b', lower):
            day = int(match[1] or match[4])
            month = MONTHS[match[2] or match[3]]
            year = int(match[5]) if match[5] else received.year
            try:
                date = dt.date(year, month, day)
                if not match[5] and (received - date).days > 180:
                    date = date.replace(year=year + 1)
                candidates.append(date)
            except ValueError:
                pass
        for weekday, index in [('monday', 0), ('tuesday', 1), ('wednesday', 2), ('thursday', 3), ('friday', 4), ('saturday', 5), ('sunday', 6)]:
            if re.search(r'\b' + weekday + r'\b', lower):
                offset = (index - received.weekday()) % 7
                if offset == 0 and 'next ' + weekday in lower:
                    offset = 7
                candidates.append(received + dt.timedelta(days=offset))
    return sorted(set(candidates))


def matches(rule, message):
    if not rule['enabled']:
        return False
    term = rule['term'].casefold()
    if rule['field'] == 'sender':
        return term == message['sender_email'].casefold()
    if rule['field'] == 'domain':
        return term.lstrip('@') == message['sender_email'].casefold().rsplit('@', 1)[-1]
    if rule['field'] == 'anywhere':
        return term in (message['subject'] + '\n' + message['body']).casefold()
    return term in message[rule['field']].casefold()


def summarize(body, subject):
    sentences = [s.strip() for s in re.split(r'(?<=[.!?])\s+|\n+', body) if len(s.strip()) > 15]
    if not sentences:
        return body[:600] or 'No readable text content.'
    words = set(re.findall(r'\w{4,}', subject.lower()))
    def weight(item):
        index, text = item
        score = sum(points for _, points, pattern in CATEGORIES if re.search(pattern, text, re.I))
        score += 12 if re.search(DEADLINE_WORDS, text, re.I) else 0
        score += len(words & set(re.findall(r'\w{4,}', text.lower()))) * 2
        return score + (4 if index == 0 else 0)
    chosen = sorted(sorted(enumerate(sentences), key=weight, reverse=True)[:3])
    return ' '.join(text for _, text in chosen)[:1000]


def prioritize(message, rules, today=None):
    today = today or dt.datetime.now().astimezone().date()
    text = message['subject'] + '\n' + message['body']
    reasons, score = [], 0
    received = dt.datetime.fromisoformat(message['received']).astimezone().date()
    dates = extract_deadlines(text, received)
    deadline = min(dates) if dates else None
    notify = False
    desired_labels = []
    for rule in rules:
        if matches(rule, message):
            score += rule['points']
            reasons.append({'text': '%s: %s' % (rule['field'].title(), rule['term']), 'points': rule['points']})
            notify |= bool(rule['notify'])
            if rule['label']:
                desired_labels.append(rule['label'])
    # Commercial calls to action outweigh incidental academic keywords.
    transactional = re.search(r'\b(password reset|verification code|security alert|sign-in attempt|payment receipt|invoice|account suspended)\b', message['subject'], re.I)
    commercial = re.search(r'\b(upgrade (?:to|your)|premium|subscribe now|special offer|limited.time offer|discount|sale ends|unlock (?:your|full|premium)|start (?:your |a )?free trial|come back to|we miss you)\b', text, re.I)
    promotions = 'CATEGORY_PROMOTIONS' in message.get('labels', [])
    provider_campaign = 'clastify' in message['sender_email'].casefold() and not re.search(r'\b(receipt|invoice|password|verification|security|your (?:order|document|submission|payment))\b', message['subject'], re.I)
    ad = bool(not transactional and (promotions or commercial or provider_campaign))
    otp = bool(re.search(r'\b(otp|one.time (?:password|code)|verification code|authentication code|security code|sign.in code|login code)\b', text, re.I))
    category = ('OTP & verification' if otp else 'Ads' if ad else
                'Account & security' if transactional else
                'School & assessments' if re.search(r'\b(school|student|exam|assessment|midterm|teacher)\b', text, re.I) else
                'Meetings & events' if re.search(r'\b(meeting|invitation|calendar|event)\b', text, re.I) else
                'Updates' if 'CATEGORY_UPDATES' in message.get('labels', []) else 'General')
    score = max(0, score)
    return {**message, 'score': score, 'level': 'Critical' if score >= 50 else 'High' if score >= 25 else 'Medium' if score >= 10 else 'Low' if score else 'Unprioritized',
            'reasons': reasons, 'deadline': deadline.isoformat() if deadline else None,
            'summary': summarize(message['body'], message['subject']),
            'notify': notify, 'desired_labels': desired_labels, 'category': category}


def load_messages(uid):
    with connect() as con:
        rows = con.execute('SELECT * FROM messages WHERE uid=?', (uid,)).fetchall()
        rules = [dict(r) for r in con.execute('SELECT * FROM rules WHERE uid=? ORDER BY id', (uid,))]
    items = []
    for row in rows:
        msg = dict(row)
        msg.pop('uid')
        msg['labels'] = json.loads(msg['labels'])
        items.append(prioritize(msg, rules))
    return sorted(items, key=lambda m: m['received'], reverse=True)


def sync_mail(uid):
    # Serialize refresh tokens, imports and label writes; throttle across tabs.
    if not SYNC_LOCK.acquire(blocking=False):
        raise AppError('A synchronization is already running. Try again shortly.', 409)
    try:
        with connect() as con:
            user = dict(con.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone())
            existing = {r['id'] for r in con.execute('SELECT id FROM messages WHERE uid=?', (uid,))}
        if time.time() - user['last_sync'] < 25:
            return
        token = access_token(uid)
        # Capture before listing, so arrivals during synchronization are caught next poll.
        checkpoint = gmail(token, '/profile')['historyId']
        latest = gmail(token, '/messages', labelIds='INBOX', maxResults=100).get('messages', [])
        ids = {m['id'] for m in latest}
        changed = ids - existing
        if user['history']:
            page = None
            try:
                while True:
                    params = {'startHistoryId': user['history'], 'maxResults': 500}
                    if page:
                        params['pageToken'] = page
                    result = gmail(token, '/history', **params)
                    for record in result.get('history', []):
                        changed.update(m['id'] for m in record.get('messages', []))
                    page = result.get('nextPageToken')
                    if not page:
                        break
            except AppError as exc:
                if exc.status != 404:
                    raise
                changed = ids
        else:
            changed = ids
        for mid in changed & ids:
            try:
                msg = normalize_message(gmail(token, '/messages/' + mid, format='full'))
            except AppError as exc:
                if exc.status == 404:
                    ids.discard(mid)
                    continue
                raise
            with connect() as con:
                con.execute('INSERT OR REPLACE INTO messages VALUES(?,?,?,?,?,?,?,?)',
                            (uid, mid, msg['subject'], msg['sender'], msg['sender_email'], msg['body'], msg['received'], json.dumps(msg['labels'])))
        with connect() as con:
            for mid in existing - ids:
                con.execute('DELETE FROM messages WHERE uid=? AND id=?', (uid, mid))
        items = load_messages(uid)
        labels = gmail(token, '/labels').get('labels', [])
        label_map = {l['name']: l['id'] for l in labels}
        for item in items:
            additions = []
            for label in set(item['desired_labels']):
                if label not in label_map:
                    created = gmail(token, '/labels', 'POST', {'name': label, 'labelListVisibility': 'labelShow', 'messageListVisibility': 'show'})
                    label_map[label] = created['id']
                if label_map[label] not in item['labels']:
                    additions.append(label_map[label])
            if additions:
                result = gmail(token, '/messages/' + item['id'] + '/modify', 'POST', {'addLabelIds': additions})
                with connect() as con:
                    con.execute('UPDATE messages SET labels=? WHERE uid=? AND id=?', (json.dumps(result['labelIds']), uid, item['id']))
        with connect() as con:
            con.execute('UPDATE users SET history=?,last_sync=? WHERE id=?', (checkpoint, time.time(), uid))
        record_notices(uid)
    finally:
        SYNC_LOCK.release()


def record_notices(uid):
    with connect() as con:
        for item in load_messages(uid):
            if item['notify']:
                con.execute('INSERT OR IGNORE INTO notices(uid,mid,title,created) VALUES(?,?,?,?)',
                            (uid, item['id'], item['sender'] + ': ' + item['subject'], time.time()))


def clean_username(value):
    return unicodedata.normalize('NFKC', str(value)).strip()


def valid_password(value):
    return (12 <= len(value) <= 200 and any(c.isupper() for c in value)
            and any(c.islower() for c in value) and any(c.isdigit() for c in value)
            and any(not c.isalnum() and not c.isspace() for c in value))


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()
    return salt + ':' + digest


def password_matches(password, stored):
    return bool(stored) and hmac.compare_digest(hash_password(password, stored.split(':')[0]), stored)


class Handler(BaseHTTPRequestHandler):
    server_version = 'IAProject'

    def log_message(self, fmt, *args):
        # Callback URLs contain short-lived authorization codes: don't log paths.
        pass

    def send(self, data, status=200, redirect=None):
        body = (json.dumps(data).encode() if not isinstance(data, str) else data.encode())
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8' if not isinstance(data, str) else 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if getattr(self, 'new_cookie', None):
            secure = '; Secure' if ORIGIN.startswith('https://') else ''
            self.send_header('Set-Cookie', 'staffroom=' + self.new_cookie + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200' + secure)
        if redirect:
            self.send_header('Location', redirect)
        self.end_headers()
        self.wfile.write(body)

    def session(self):
        jar = cookies.SimpleCookie()
        try:
            jar.load(self.headers.get('Cookie', ''))
        except cookies.CookieError:
            pass
        raw = jar['staffroom'].value if 'staffroom' in jar else ''
        key = hashlib.sha256(raw.encode()).hexdigest()
        with connect() as con:
            row = con.execute('SELECT * FROM sessions WHERE token=? AND expires>?', (key, time.time())).fetchone()
            if row:
                return dict(row)
            raw = secrets.token_urlsafe(32)
            key = hashlib.sha256(raw.encode()).hexdigest()
            con.execute('DELETE FROM sessions WHERE expires<?', (time.time(),))
            con.execute('INSERT INTO sessions(token,csrf,expires) VALUES(?,?,?)', (key, secrets.token_urlsafe(32), time.time() + 43200))
            self.new_cookie = raw
            return dict(con.execute('SELECT * FROM sessions WHERE token=?', (key,)).fetchone())

    def rotate_session(self, uid, verified=False):
        raw = secrets.token_urlsafe(32)
        with connect() as con:
            con.execute('DELETE FROM sessions WHERE token=?', (self.sess['token'],))
            con.execute('INSERT INTO sessions(token,uid,csrf,expires,verified) VALUES(?,?,?,?,?)',
                        (hashlib.sha256(raw.encode()).hexdigest(), uid, secrets.token_urlsafe(32), time.time() + 43200, time.time() if verified else 0))
        self.new_cookie = raw

    def user(self, complete=True):
        if not self.sess['uid']:
            raise AppError('Please sign in first.', 401)
        with connect() as con:
            user = con.execute('SELECT * FROM users WHERE id=?', (self.sess['uid'],)).fetchone()
        if not user:
            raise AppError('Please sign in again.', 401)
        if complete and not user['username']:
            raise AppError('Finish setting up your profile first.', 403)
        return dict(user)

    def throttle(self, name):
        now = time.time()
        key = self.client_address[0] + ':' + name
        with connect() as con:
            row = con.execute('SELECT * FROM attempts WHERE key=?', (key,)).fetchone()
            if row and now - row['started'] < 300 and row['count'] >= 15:
                raise AppError('Too many attempts. Try again in five minutes.', 429)
            if not row or now - row['started'] >= 300:
                con.execute('INSERT OR REPLACE INTO attempts VALUES(?,1,?)', (key, now))
            else:
                con.execute('UPDATE attempts SET count=count+1 WHERE key=?', (key,))

    def do_GET(self):
        self.dispatch('GET')

    def do_POST(self):
        self.dispatch('POST')

    def dispatch(self, method):
        self.new_cookie = None
        try:
            if method == 'GET' and parse.urlparse(self.path).path == '/healthz':
                with connect() as con:
                    con.execute('SELECT 1').fetchone()
                return self.send({'ok': True})
            if self.headers.get('Host', '').lower() != HOST.lower():
                raise AppError('Open this app using its configured public URL.', 403)
            self.sess = self.session()
            url = parse.urlparse(self.path)
            path = url.path
            query = parse.parse_qs(url.query)
            body = {}
            if method == 'POST':
                if self.headers.get('Origin') not in (None, ORIGIN):
                    raise AppError('Request origin rejected.', 403)
                if not hmac.compare_digest(self.headers.get('X-CSRF-Token', ''), self.sess['csrf']):
                    raise AppError('Session changed. Reload the page and try again.', 403)
                length = int(self.headers.get('Content-Length', 0))
                if length < 0 or length > 200000:
                    raise AppError('Request too large.', 413)
                body = json.loads(self.rfile.read(length) or b'{}')
                if not isinstance(body, dict):
                    raise AppError('Expected a JSON object.')
            if method == 'GET' and path == '/':
                return self.send(PAGE)
            if method == 'GET' and path == '/auth/google':
                return self.begin_google(query)
            if method == 'GET' and path == '/auth/callback':
                return self.finish_google(query)
            if method == 'GET' and path == '/api/state':
                user = self.user(False) if self.sess['uid'] else None
                public = {k: user[k] for k in ('id', 'email', 'name', 'username', 'avatar', 'theme', 'last_sync')} if user else None
                if public:
                    public['connected'] = bool(user['tokens'])
                    public['can_reset_password'] = time.time() - self.sess['verified'] < 600
                return self.send({'csrf': self.sess['csrf'], 'user': public, 'configured': google_is_configured()})
            if method == 'POST' and path == '/api/login':
                self.throttle('login')
                with connect() as con:
                    user = con.execute('SELECT * FROM users WHERE username=? COLLATE NOCASE', (clean_username(body.get('username', '')),)).fetchone()
                stored = user['password'] if user else None
                # Perform comparable work for unknown usernames.
                valid = password_matches(str(body.get('password', '')), stored or hash_password('unused'))
                if not user or not valid:
                    raise AppError('Incorrect username or app password.', 401)
                self.rotate_session(user['id'])
                return self.send({'ok': True})
            if method == 'GET' and path == '/api/username':
                user = self.user(False)
                username = clean_username(query.get('value', [''])[0])
                valid = 1 <= len(username) <= 60 and not any(unicodedata.category(c).startswith('C') for c in username)
                with connect() as con:
                    rows = con.execute('SELECT id,username FROM users WHERE username IS NOT NULL').fetchall()
                available = valid and not any(clean_username(r['username']).casefold() == username.casefold() and r['id'] != user['id'] for r in rows)
                return self.send({'available': available, 'valid': valid})
            if method == 'POST' and path == '/api/profile':
                user = self.user(False)
                username = clean_username(body.get('username', ''))
                password = str(body.get('password', ''))
                if not 1 <= len(username) <= 60 or any(unicodedata.category(c).startswith('C') for c in username):
                    raise AppError('Choose a username of 1?60 visible characters.')
                if not valid_password(password):
                    raise AppError('Password needs 12?200 characters, uppercase, lowercase, a number and a symbol.')
                if user['password'] and time.time() - self.sess['verified'] >= 600 and not password_matches(str(body.get('current_password', '')), user['password']):
                    raise AppError('Enter your current app password to change credentials.', 403)
                with connect() as con:
                    con.execute('BEGIN IMMEDIATE')
                    if any(clean_username(r['username']).casefold() == username.casefold() for r in con.execute('SELECT username FROM users WHERE username IS NOT NULL AND id<>?', (user['id'],))):
                        raise AppError('That username is already taken.')
                    try:
                        con.execute('UPDATE users SET username=?,password=? WHERE id=?', (username, hash_password(password), user['id']))
                    except sqlite3.IntegrityError:
                        raise AppError('That username is already taken.') from None
                    con.execute('DELETE FROM sessions WHERE uid=? AND token<>?', (user['id'], self.sess['token']))
                self.rotate_session(user['id'])
                return self.send({'ok': True})
            if method == 'POST' and path == '/api/logout':
                self.rotate_session(None)
                return self.send({'ok': True})
            user = self.user()
            uid = user['id']
            if method == 'GET' and path == '/api/inbox':
                record_notices(uid)
                items = load_messages(uid)
                with connect() as con:
                    rules = [dict(r) for r in con.execute('SELECT * FROM rules WHERE uid=? ORDER BY id DESC', (uid,))]
                    notices = [dict(r) for r in con.execute('SELECT * FROM notices WHERE uid=? ORDER BY created DESC LIMIT 50', (uid,))]
                label_names = {}
                # Cache Gmail label names locally in the UI response, with IDs as fallback.
                if getattr(self.server, 'label_cache', {}).get(uid):
                    label_names = self.server.label_cache[uid]
                return self.send({'messages': items, 'rules': rules, 'notices': notices, 'label_names': label_names, 'last_sync': user['last_sync']})
            if method == 'POST' and path == '/api/sync':
                sync_mail(uid)
                token = access_token(uid)
                labels = gmail(token, '/labels').get('labels', [])
                self.server.label_cache[uid] = {l['id']: l['name'] for l in labels}
                return self.send({'ok': True})
            if path == '/api/labels' and method in ('GET', 'POST'):
                token = access_token(uid)
                if method == 'POST':
                    name = str(body.get('name', '')).strip()
                    if not name or len(name) > 80 or any(ord(c) < 32 for c in name):
                        raise AppError('Enter a label name of 1?80 visible characters.')
                    gmail(token, '/labels', 'POST', {'name': name, 'labelListVisibility': 'labelShow', 'messageListVisibility': 'show'})
                labels = gmail(token, '/labels').get('labels', [])
                self.server.label_cache[uid] = {l['id']: l['name'] for l in labels}
                return self.send({'labels': [l for l in labels if l.get('type') == 'user']})
            if method == 'POST' and path == '/api/rules/save':
                field = str(body.get('field', ''))
                term = str(body.get('term', '')).strip()
                points = int(body.get('points', 0))
                label = str(body.get('label', '')).strip()
                if field not in ('subject', 'body', 'sender', 'domain', 'anywhere') or not 1 <= len(term) <= 200 or not -100 <= points <= 100:
                    raise AppError('Choose a field, enter a match, and use points from -100 to 100.')
                if field == 'sender' and not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', term):
                    raise AppError('Sender rules require an exact email address.')
                if len(label) > 80 or any(ord(c) < 32 for c in label) or label.upper() in {'INBOX', 'UNREAD', 'SENT', 'TRASH', 'SPAM', 'DRAFT', 'STARRED', 'IMPORTANT'}:
                    raise AppError('Label names can contain up to 80 visible characters.')
                with connect() as con:
                    values = (field, term, points, label, int(bool(body.get('notify'))), int(bool(body.get('enabled', True))))
                    if body.get('id'):
                        con.execute('UPDATE rules SET field=?,term=?,points=?,label=?,notify=?,enabled=? WHERE id=? AND uid=?', values + (int(body['id']), uid))
                    else:
                        if con.execute('SELECT count(*) FROM rules WHERE uid=?', (uid,)).fetchone()[0] >= 100:
                            raise AppError('Maximum 100 rules. Remove an old rule first.')
                        con.execute('INSERT INTO rules(field,term,points,label,notify,enabled,uid) VALUES(?,?,?,?,?,?,?)', values + (uid,))
                    con.execute("UPDATE users SET last_sync=0 WHERE id=?", (uid,))
                return self.send({'ok': True})
            if method == 'POST' and path == '/api/rules/delete':
                with connect() as con:
                    con.execute('DELETE FROM rules WHERE id=? AND uid=?', (int(body['id']), uid))
                return self.send({'ok': True})
            if method == 'GET' and path == '/api/mail':
                mid = query.get('id', [''])[0]
                if not re.fullmatch(r'[A-Za-z0-9_-]{1,100}', mid):
                    raise AppError('Invalid message ID.')
                msg = normalize_message(gmail(access_token(uid), '/messages/' + mid, format='full'))
                with connect() as con:
                    con.execute('INSERT OR REPLACE INTO messages VALUES(?,?,?,?,?,?,?,?)',
                        (uid, mid, msg['subject'], msg['sender'], msg['sender_email'], msg['body'], msg['received'], json.dumps(msg['labels'])))
                    rules = [dict(r) for r in con.execute('SELECT * FROM rules WHERE uid=?', (uid,))]
                return self.send({'message': prioritize(msg, rules)})
            if method == 'POST' and path == '/api/bulk/preview':
                field = body.get('field')
                term = str(body.get('term', '')).strip()
                if field not in ('sender', 'topic') or not 1 <= len(term) <= 200 or any(c in term for c in ['"', '\\', '\r', '\n']):
                    raise AppError('Enter an email address or a topic phrase without quotes or backslashes.')
                if field == 'sender' and not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', term):
                    raise AppError('Enter the sender email address.')
                token = access_token(uid)
                query_text = ('from:' if field == 'sender' else '') + '"' + term + '" -in:trash -in:spam -in:sent -in:drafts'
                result = gmail(token, '/messages', q=query_text, maxResults=500)
                ids, preview = [], []
                for item in result.get('messages', []):
                    try:
                        raw = gmail(token, '/messages/' + item['id'], format='metadata', metadataHeaders=['From', 'Subject'])
                    except AppError as exc:
                        if exc.status == 404:
                            continue
                        raise
                    headers = {h['name'].lower(): h['value'] for h in raw.get('payload', {}).get('headers', [])}
                    address = email.utils.parseaddr(headers.get('from', ''))[1]
                    if field == 'sender' and address.casefold() != term.casefold():
                        continue
                    ids.append(item['id'])
                    preview.append({'id': item['id'], 'sender': headers.get('from', ''), 'subject': headers.get('subject', '(No subject)')})
                plan = secrets.token_urlsafe(32)
                with connect() as con:
                    con.execute('DELETE FROM bulk_plans WHERE expires<?', (time.time(),))
                    con.execute('INSERT INTO bulk_plans VALUES(?,?,?,?)', (plan, uid, json.dumps(ids), time.time()+900))
                return self.send({'plan': plan, 'messages': preview, 'has_more': bool(result.get('nextPageToken'))})
            if method == 'POST' and path == '/api/bulk/trash':
                plan = str(body.get('plan', ''))
                token = access_token(uid)
                moved, failure = 0, None
                with SYNC_LOCK:
                    with connect() as con:
                        row = con.execute('SELECT * FROM bulk_plans WHERE token=? AND uid=? AND expires>?', (plan, uid, time.time())).fetchone()
                    if not row:
                        raise AppError('Preview expired. Preview your matches again.')
                    ids = json.loads(row['ids'])
                    for mid in list(ids):
                        try:
                            gmail(token, '/messages/' + mid + '/trash', 'POST', {})
                        except AppError as exc:
                            if exc.status != 404:
                                failure = str(exc)
                                break
                        else:
                            moved += 1
                        ids.remove(mid)
                        with connect() as con:
                            con.execute('DELETE FROM messages WHERE uid=? AND id=?', (uid, mid))
                            con.execute('UPDATE bulk_plans SET ids=? WHERE token=? AND uid=?', (json.dumps(ids), plan, uid))
                return self.send({'moved': moved, 'remaining': len(ids), 'error_message': failure})
            if path == '/api/blocks' and method in ('GET', 'POST'):
                if method == 'GET':
                    return self.send(blocked_sender_list(uid))
                if method == 'POST':
                    sender = str(body.get('sender', '')).strip().casefold()
                    if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', sender):
                        raise AppError('Enter a valid sender email address.')
                    with connect() as con:
                        saved = con.execute('SELECT filter_id FROM blocked_senders WHERE uid=? AND sender=?', (uid, sender)).fetchone()
                    token = access_token(uid)
                    with connect() as con:
                        encrypted = con.execute('SELECT tokens FROM users WHERE id=?', (uid,)).fetchone()['tokens']
                    if 'https://www.googleapis.com/auth/gmail.settings.basic' not in json.loads(protect(encrypted, True)).get('scope', '').split():
                        raise AppError('Enable Gmail filter access with the Google connection button in this panel, then try again.', 403)
                    if body.get('unblock') and saved:
                        if not body.get('record_only'):
                            try:
                                gmail(token, '/settings/filters/' + parse.quote(saved['filter_id'], safe=''), 'DELETE')
                            except AppError as exc:
                                if exc.status != 404:
                                    raise
                        with connect() as con:
                            con.execute('DELETE FROM blocked_senders WHERE uid=? AND sender=?', (uid, sender))
                    elif not body.get('unblock') and not saved:
                        result = gmail(token, '/settings/filters', 'POST', {'criteria': {'from': sender}, 'action': {'addLabelIds': ['TRASH'], 'removeLabelIds': ['INBOX']}})
                        with connect() as con:
                            con.execute('INSERT INTO blocked_senders VALUES(?,?,?)', (uid, sender, result['id']))
                with connect() as con:
                    senders = [r['sender'] for r in con.execute('SELECT sender FROM blocked_senders WHERE uid=? ORDER BY sender', (uid,))]
                return self.send({'senders': senders})
            if method == 'GET' and path == '/api/reply-details':
                mid = query.get('id', [''])[0]
                with connect() as con:
                    found = con.execute('SELECT id FROM messages WHERE uid=? AND id=?', (uid, mid)).fetchone()
                if not found:
                    raise AppError('Message not found.', 404)
                original = gmail(access_token(uid), '/messages/' + mid, format='metadata', metadataHeaders=['Reply-To', 'From'])
                headers = {h['name'].lower(): h['value'] for h in original.get('payload', {}).get('headers', [])}
                return self.send({'recipient': email.utils.parseaddr(headers.get('reply-to') or headers.get('from', ''))[1]})
            if method == 'POST' and path == '/api/message':
                mid = str(body.get('id', ''))
                with connect() as con:
                    found = con.execute('SELECT * FROM messages WHERE uid=? AND id=?', (uid, mid)).fetchone()
                if not found:
                    raise AppError('Message not found.', 404)
                token = access_token(uid)
                action = body.get('action', 'read')
                if action == 'reply':
                    text = str(body.get('text', '')).strip()
                    if not text or len(text) > 50000:
                        raise AppError('Enter a reply of 1?50,000 characters.')
                    original = gmail(token, '/messages/' + mid, format='metadata', metadataHeaders=['Reply-To', 'From', 'Subject', 'Message-ID', 'References'])
                    headers = {h['name'].lower(): h['value'] for h in original.get('payload', {}).get('headers', [])}
                    recipient = email.utils.parseaddr(headers.get('reply-to') or headers.get('from', ''))[1]
                    if not recipient or '@' not in recipient:
                        raise AppError('This message has no valid reply address.')
                    reply = EmailMessage()
                    reply['From'] = user['email']
                    reply['To'] = recipient
                    subject = headers.get('subject', found['subject'])
                    reply['Subject'] = subject if subject.lower().startswith('re:') else 'Re: ' + subject
                    if headers.get('message-id'):
                        reply['In-Reply-To'] = headers['message-id']
                        reply['References'] = (headers.get('references', '') + ' ' + headers['message-id']).strip()
                    reply.set_content(text)
                    gmail(token, '/messages/send', 'POST', {'raw': base64.urlsafe_b64encode(reply.as_bytes()).decode(), 'threadId': original['threadId']})
                    return self.send({'ok': True, 'recipient': recipient})
                if action == 'trash':
                    with SYNC_LOCK:
                        gmail(token, '/messages/' + mid + '/trash', 'POST', {})
                        with connect() as con:
                            con.execute('DELETE FROM messages WHERE uid=? AND id=?', (uid, mid))
                    return self.send({'ok': True})
                if action == 'star':
                    params = {'addLabelIds': ['STARRED']} if body.get('starred', True) else {'removeLabelIds': ['STARRED']}
                elif action == 'label':
                    label_id = str(body.get('label_id', ''))
                    allowed = {l['id'] for l in gmail(token, '/labels').get('labels', []) if l.get('type') == 'user'}
                    if label_id not in allowed:
                        raise AppError('Choose an existing custom Gmail label.')
                    params = {'removeLabelIds' if body.get('remove') else 'addLabelIds': [label_id]}
                elif action == 'read':
                    params = {'removeLabelIds': ['UNREAD']} if body.get('read', True) else {'addLabelIds': ['UNREAD']}
                else:
                    raise AppError('Unknown message action.')
                result = gmail(token, '/messages/' + mid + '/modify', 'POST', params)
                with connect() as con:
                    con.execute('UPDATE messages SET labels=? WHERE uid=? AND id=?', (json.dumps(result['labelIds']), uid, mid))
                return self.send({'ok': True})
            if method == 'POST' and path == '/api/notices/seen':
                with connect() as con:
                    con.execute('UPDATE notices SET seen=1 WHERE uid=?', (uid,))
                return self.send({'ok': True})
            if method == 'POST' and path == '/api/settings':
                theme = body.get('theme', 'light')
                if theme not in ('light', 'dark'):
                    raise AppError('Invalid theme.')
                avatar = str(body.get('avatar', user['avatar']))
                if avatar and not re.fullmatch(r'data:image/(?:png|jpeg|webp);base64,[A-Za-z0-9+/=]+', avatar):
                    raise AppError('Choose a PNG, JPEG or WebP profile image.')
                if len(avatar) > 150000:
                    raise AppError('Use a profile image smaller than 100 KB.')
                with connect() as con:
                    con.execute('UPDATE users SET theme=?,avatar=? WHERE id=?', (theme, avatar, uid))
                return self.send({'ok': True})
            if method == 'POST' and path == '/api/disconnect':
                # Finish any active sync first so it cannot repopulate a cleared cache.
                with SYNC_LOCK:
                    with connect() as con:
                        current = con.execute('SELECT tokens FROM users WHERE id=?', (uid,)).fetchone()
                    if current['tokens']:
                        tokens = json.loads(protect(current['tokens'], True))
                        try:
                            http_json('https://oauth2.googleapis.com/revoke', 'POST', {'token': tokens.get('refresh_token', tokens['access_token'])}, form=True)
                        except AppError as exc:
                            if exc.status != 400:
                                raise AppError('Google revocation could not be confirmed. Try again or remove access in your Google Account.', 502) from None
                    with connect() as con:
                        con.execute("UPDATE users SET tokens=NULL,history='',last_sync=0 WHERE id=?", (uid,))
                        con.execute('DELETE FROM messages WHERE uid=?', (uid,))
                        con.execute('DELETE FROM notices WHERE uid=?', (uid,))
                self.server.label_cache.pop(uid, None)
                return self.send({'ok': True})
            raise AppError('Page not found.', 404)
        except AppError as exc:
            self.send({'error': str(exc)}, exc.status)
        except (ValueError, TypeError, KeyError, OverflowError):
            self.send({'error': 'Invalid request or unexpected Google response. Check your input and retry.'}, 400)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:
            print('Request failed:', type(exc).__name__)
            self.send({'error': 'The request could not be completed. Check the terminal and retry.'}, 500)

    def begin_google(self, query):
        self.throttle('google')
        cfg = google_config()
        state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
        mode = query.get('mode', ['signup'])[0]
        if mode not in ('signup', 'signin', 'reconnect'):
            raise AppError('Invalid sign-in mode.')
        if mode == 'reconnect':
            self.user()
        with connect() as con:
            con.execute('UPDATE sessions SET state=?,verifier=?,oauth_time=?,mode=?,reconnect=? WHERE token=?',
                        (state, verifier, time.time(), mode, self.sess['uid'] if mode == 'reconnect' else 0, self.sess['token']))
        params = {'client_id': cfg['client_id'], 'redirect_uri': REDIRECT, 'response_type': 'code',
                  'scope': SCOPE + (' https://www.googleapis.com/auth/gmail.settings.basic' if query.get('filters') == ['1'] else ''), 'include_granted_scopes': 'true', 'state': state, 'access_type': 'offline', 'prompt': 'consent select_account',
                  'code_challenge': base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('='),
                  'code_challenge_method': 'S256'}
        self.send('', 302, 'https://accounts.google.com/o/oauth2/v2/auth?' + parse.urlencode(params))

    def finish_google(self, query):
        state = query.get('state', [''])[0]
        if not self.sess['state'] or not hmac.compare_digest(state, self.sess['state']) or time.time() - (self.sess['oauth_time'] or 0) > 600:
            raise AppError('Google sign-in expired. Return to the app and try again.', 403)
        with connect() as con:
            con.execute('UPDATE sessions SET state=NULL,verifier=NULL WHERE token=?', (self.sess['token'],))
        if 'error' in query:
            return self.send('', 302, '/?auth_error=denied')
        cfg = google_config()
        tokens = http_json('https://oauth2.googleapis.com/token', 'POST', {
            'client_id': cfg['client_id'], 'client_secret': cfg['client_secret'], 'code': query.get('code', [''])[0],
            'redirect_uri': REDIRECT, 'grant_type': 'authorization_code', 'code_verifier': self.sess['verifier']}, form=True)
        if 'https://www.googleapis.com/auth/gmail.modify' not in tokens.get('scope', '').split():
            raise AppError('Gmail permission was not granted. Return and connect again with Gmail access.', 403)
        info = http_json('https://openidconnect.googleapis.com/v1/userinfo', token=tokens['access_token'])
        if not info.get('email_verified') or not info.get('sub'):
            raise AppError('Google could not verify this email account.', 403)
        with connect() as con:
            existing = con.execute('SELECT * FROM users WHERE sub=?', (info['sub'],)).fetchone()
            if self.sess['mode'] == 'signin' and not existing:
                raise AppError('This Google account has no profile yet. Go back and choose Sign up.', 403)
            if self.sess['reconnect'] and (not existing or existing['id'] != self.sess['reconnect']):
                raise AppError('Reconnect using the same Google account as your profile.', 403)
            if existing:
                uid = existing['id']
                con.execute('UPDATE users SET email=?,name=? WHERE id=?', (info['email'], info.get('name', info['email']), uid))
                if not tokens.get('refresh_token') and existing['tokens']:
                    old = json.loads(protect(existing['tokens'], True))
                    if old.get('refresh_token'):
                        tokens['refresh_token'] = old['refresh_token']
            else:
                uid = con.execute('INSERT INTO users(sub,email,name) VALUES(?,?,?)', (info['sub'], info['email'], info.get('name', info['email']))).lastrowid
        tokens['expires_at'] = time.time() + tokens.get('expires_in', 3600)
        save_tokens(uid, tokens)
        self.rotate_session(uid, verified=True)
        return self.send('', 302, '/')


def configure():
    from getpass import getpass
    print('\nCreate a Web application OAuth client in Google Cloud.')
    print('Authorized JavaScript origin:', ORIGIN)
    print('Authorized redirect URI:   ', REDIRECT)
    print('Enable Gmail API. Add yourself as a test user. Scope:', SCOPE)
    client_id = input('\nPaste OAuth client ID: ').strip()
    client_secret = getpass('Paste OAuth client secret (hidden): ').strip()
    if not client_id.endswith('.apps.googleusercontent.com') or not client_secret:
        raise SystemExit('Invalid client ID or empty secret. Nothing saved.')
    encrypted = protect(json.dumps({'client_id': client_id, 'client_secret': client_secret}))
    DATA.mkdir(exist_ok=True)
    CONFIG.write_text(encrypted)
    print('Saved using Windows encryption. Run: python app.py')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--configure', action='store_true', help='Save your Google OAuth client securely on Windows')
    args = parser.parse_args()
    if args.configure:
        configure()
    else:
        if HOSTED:
            if not os.environ.get('RAILWAY_VOLUME_MOUNT_PATH') and not os.environ.get('DATA_DIR'):
                raise SystemExit('Attach a persistent Railway volume at /data before starting.')
            if not ORIGIN.startswith('https://') or not HOST:
                raise SystemExit('Generate a Railway public domain or set APP_ORIGIN to your exact https:// public URL.')
            if not os.environ.get('TOKEN_ENCRYPTION_KEY'):
                raise SystemExit('Set TOKEN_ENCRYPTION_KEY before starting.')
            if not google_is_configured():
                raise SystemExit('Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET before starting.')
        init_db()
        server = ThreadingHTTPServer(('0.0.0.0' if HOSTED else '127.0.0.1', PORT), Handler)
        server.daemon_threads = True
        server.label_cache = {}
        print('IA Project is running at ' + ORIGIN)
        print('Google: ' + ('configured' if google_is_configured() else 'not configured; run python app.py --configure in another terminal'))
        print('Press Ctrl+C to stop.')
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.server_close()
