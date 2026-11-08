"""Run with python -m unittest -v. Uses fake Google responses, never a mailbox."""
import base64
import datetime as dt
from http.cookiejar import CookieJar
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib import error, parse, request

import app


def message(body='Please review the attached notes.', subject='School update', mid='abc'):
    return {'id': mid, 'subject': subject, 'sender': 'Principal', 'sender_email': 'principal@school.test',
            'body': body, 'received': '2026-11-01T10:00:00+00:00', 'labels': ['INBOX', 'UNREAD']}


def rule(field='subject', term='update', points=5, **extra):
    return {'field': field, 'term': term, 'points': points, 'label': '', 'notify': 0, 'enabled': 1, **extra}


class AlgorithmTests(unittest.TestCase):
    def test_deadline_increases_without_new_email(self):
        msg = message('Please submit your report. The deadline is in 11 days.')
        first = app.prioritize(msg, [], dt.date(2026, 11, 1))
        later = app.prioritize(msg, [], dt.date(2026, 11, 8))
        self.assertEqual(first['deadline'], '2026-11-12')
        self.assertEqual(first['score'], 0)
        self.assertEqual(later['score'], 0)

    def test_overdue_and_urgent(self):
        result = app.prioritize(message('Urgent! Your submission is overdue. It was due 2026-10-30.'), [], dt.date(2026, 11, 1))
        self.assertEqual(result['score'], 0)

    def test_fire_drill_distinguished_from_emergency(self):
        drill = app.prioritize(message('A fire drill is scheduled tomorrow.'), [], dt.date(2026, 11, 1))
        emergency = app.prioritize(message('Urgent: fire in the science lab.'), [])
        self.assertNotIn('Safety concern', [r['text'] for r in drill['reasons']])
        self.assertEqual(drill['score'], 0)
        self.assertEqual(emergency['score'], 0)

    def test_categories_count_once_and_word_boundaries(self):
        self.assertEqual(app.prioritize(message('Urgent urgent ASAP immediately'), [])['score'], 0)
        self.assertEqual(app.prioritize(message('The firefighter sent a newsletter.'), [])['score'], 0)

    def test_exact_sender_and_case_insensitive_phrase(self):
        msg = message(subject='SCHOOL UPDATE')
        rules = [rule(), rule('sender', 'PRINCIPAL@SCHOOL.TEST', 20), rule('sender', 'principal', 100)]
        self.assertEqual(app.prioritize(msg, rules)['score'], 25)

    def test_disabled_and_negative_rules(self):
        msg = message()
        self.assertEqual(app.prioritize(msg, [rule(points=10, enabled=0)])['score'], 0)
        self.assertEqual(app.prioritize(msg, [rule(points=-100)])['score'], 0)

    def test_supported_date_patterns_and_invalid_dates(self):
        anchor = dt.date(2026, 11, 1)
        self.assertEqual(app.extract_deadlines('Please submit by November 12, 2026.', anchor), [dt.date(2026, 11, 12)])
        self.assertEqual(app.extract_deadlines('Exam on 12 November 2026.', anchor), [dt.date(2026, 11, 12)])
        self.assertEqual(app.extract_deadlines('Meeting due Monday', anchor), [dt.date(2026, 11, 2)])
        self.assertEqual(app.extract_deadlines('Deadline 2026-02-30 or 03/04.', anchor), [])
        self.assertEqual(app.extract_deadlines('Newsletter published 2026-11-12.', anchor), [])

    def test_extract_summary_is_original_text(self):
        body = 'Welcome to this week’s newsletter. Please submit your assessment by tomorrow. There is a safety hazard in the lab. Enjoy your weekend.'
        summary = app.summarize(body, 'Assessment deadline')
        self.assertIn('Please submit your assessment by tomorrow.', summary)
        for sentence in summary.split('. '):
            self.assertIn(sentence, body)

    def test_html_is_not_executed_and_attachments_ignored(self):
        def part(mime, content, filename=''):
            return {'mimeType': mime, 'filename': filename, 'body': {'data': base64.urlsafe_b64encode(content.encode()).decode()}}
        payload = {'parts': [part('text/html', '<p>Hello</p><script>bad()</script><p>World</p>'), part('text/plain', 'secret attachment', 'notes.txt')]}
        text = app.message_body(payload)
        self.assertIn('Hello', text)
        self.assertNotIn('bad', text)
        self.assertNotIn('secret', text)

    def test_promotional_keywords_do_not_gain_school_priority(self):
        msg = message('Urgent! Upgrade to premium for your exams. Offer ends tomorrow.')
        result = app.prioritize(msg, [rule(points=100, notify=1)])
        self.assertEqual(result['category'], 'Ads')
        self.assertEqual(result['score'], 100)
        self.assertTrue(result['notify'])
        msg['sender_email'] = 'hello@clastify.com'
        msg['body'] = 'Explore our exam resources.'
        self.assertEqual(app.prioritize(msg, [])['category'], 'Ads')
        msg['subject'] = 'Password reset verification code'
        self.assertNotEqual(app.prioritize(msg, [])['category'], 'Ads')

    def test_password_requirements(self):
        self.assertTrue(app.valid_password('My school password 2026!'))
        self.assertFalse(app.valid_password('all lowercase long password'))
        self.assertFalse(app.valid_password('Short1!'))

    def test_scrypt_salted_and_verified(self):
        first = app.hash_password('a unique app password')
        self.assertNotEqual(first, app.hash_password('a unique app password'))
        self.assertTrue(app.password_matches('a unique app password', first))
        self.assertFalse(app.password_matches('wrong', first))

    @unittest.skipUnless(os.name == 'nt', 'Windows token encryption')
    def test_dpapi_roundtrip(self):
        try:
            encrypted = app.protect('a fake refresh token')
        except app.AppError as exc:
            if 'error 2)' in str(exc):
                self.skipTest('Windows user encryption profile is unavailable inside this sandbox (error 2)')
            raise
        self.assertNotIn('fake', encrypted)
        self.assertEqual(app.protect(encrypted, True), 'a fake refresh token')


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.original = app.DATA, app.DB, app.CONFIG
        app.DATA = Path(self.tmp.name)
        app.DB = app.DATA / 'test.db'
        app.CONFIG = app.DATA / 'google.json'
        app.init_db()
        with app.connect() as con:
            self.uid = con.execute("INSERT INTO users(sub,email,name,username,password) VALUES('google-sub','teacher@school.test','Teacher','teacher',?)", (app.hash_password('test-only password'),)).lastrowid

    def tearDown(self):
        app.DATA, app.DB, app.CONFIG = self.original
        self.tmp.cleanup()

    def fake_gmail(self, token, path, method='GET', payload=None, **params):
        if path == '/profile':
            return {'historyId': '100'}
        if path == '/messages':
            return {'messages': [{'id': 'abc'}]}
        if path == '/messages/abc':
            text = 'Urgent safety hazard in the school. Please act immediately.'
            return {'id': 'abc', 'internalDate': str(int(time.time()*1000)), 'labelIds': ['INBOX', 'UNREAD'],
                    'payload': {'mimeType': 'text/plain', 'headers': [{'name': 'Subject', 'value': 'Urgent safety hazard'}, {'name': 'From', 'value': 'Principal <principal@school.test>'}],
                                'body': {'data': base64.urlsafe_b64encode(text.encode()).decode()}}}
        if path == '/labels' and method == 'GET':
            return {'labels': []}
        if path == '/labels' and method == 'POST':
            return {'id': 'Label_1', 'name': payload['name']}
        if path == '/messages/abc/modify':
            return {'labelIds': ['INBOX', 'UNREAD', 'Label_1']}
        if path == '/history':
            return {'historyId': '101', 'history': []}
        raise AssertionError((path, method))

    def test_real_sync_path_with_fake_google_and_notification_dedup(self):
        with app.connect() as con:
            con.execute("INSERT INTO rules(uid,field,term,points,label,notify) VALUES(?,'sender','principal@school.test',20,'Staffroom/Leadership',1)", (self.uid,))
        with patch.object(app, 'access_token', return_value='fake'), patch.object(app, 'gmail', side_effect=self.fake_gmail) as mock:
            app.sync_mail(self.uid)
            items = app.load_messages(self.uid)
            self.assertEqual(len(items), 1)
            self.assertIn('Label_1', items[0]['labels'])
            self.assertEqual(items[0]['score'], 20)
            self.assertTrue(any(c.args[1] == '/messages/abc/modify' for c in mock.call_args_list))
            app.record_notices(self.uid)
            with app.connect() as con:
                self.assertEqual(con.execute('SELECT count(*) FROM notices').fetchone()[0], 1)
                con.execute('UPDATE users SET last_sync=0')
            mock.reset_mock()
            app.sync_mail(self.uid)
            self.assertFalse(any(c.args[1] == '/messages/abc' for c in mock.call_args_list))
            self.assertFalse(any(c.args[1].endswith('/modify') for c in mock.call_args_list))

    def test_expired_history_refreshes_and_removed_inbox_clears(self):
        with patch.object(app, 'access_token', return_value='fake'), patch.object(app, 'gmail', side_effect=self.fake_gmail):
            app.sync_mail(self.uid)
        with app.connect() as con:
            con.execute('UPDATE users SET last_sync=0')
        def expired(*args, **kwargs):
            if args[1] == '/history':
                raise app.AppError('Expired history', 404)
            return self.fake_gmail(*args, **kwargs)
        with patch.object(app, 'access_token', return_value='fake'), patch.object(app, 'gmail', side_effect=expired) as mock:
            app.sync_mail(self.uid)
            self.assertTrue(any(c.args[1] == '/messages/abc' for c in mock.call_args_list))
        with app.connect() as con:
            con.execute('UPDATE users SET last_sync=0')
        def empty(*args, **kwargs):
            if args[1] == '/messages':
                return {}
            return self.fake_gmail(*args, **kwargs)
        with patch.object(app, 'access_token', return_value='fake'), patch.object(app, 'gmail', side_effect=empty):
            app.sync_mail(self.uid)
        self.assertEqual(app.load_messages(self.uid), [])

    def test_access_token_refresh_preserves_refresh_token(self):
        stored = {'access_token': 'old', 'refresh_token': 'refresh', 'expires_at': 0}
        with app.connect() as con:
            con.execute('UPDATE users SET tokens=? WHERE id=?', (json.dumps(stored), self.uid))
        with patch.object(app, 'protect', side_effect=lambda value, decrypt=False: value), patch.object(app, 'google_config', return_value={'client_id': 'client', 'client_secret': 'secret'}), patch.object(app, 'http_json', return_value={'access_token': 'new', 'expires_in': 3600}) as mock:
            self.assertEqual(app.access_token(self.uid), 'new')
            self.assertEqual(mock.call_args.args[2]['grant_type'], 'refresh_token')
            self.assertEqual(app.access_token(self.uid), 'new')
            self.assertEqual(mock.call_count, 1)
        with app.connect() as con:
            saved = json.loads(con.execute('SELECT tokens FROM users WHERE id=?', (self.uid,)).fetchone()[0])
            self.assertEqual(saved['refresh_token'], 'refresh')


class HTTPTests(DatabaseTests):
    # Inherit database setup, but don't run its cases twice.
    test_real_sync_path_with_fake_google_and_notification_dedup = None
    test_expired_history_refreshes_and_removed_inbox_clears = None
    test_access_token_refresh_preserves_refresh_token = None

    def setUp(self):
        super().setUp()
        self.server = app.ThreadingHTTPServer(('127.0.0.1', 0), app.Handler)
        self.server.label_cache = {}
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.client = request.build_opener(request.HTTPCookieProcessor(CookieJar()))
        self.csrf = self.call('/api/state')[1]['csrf']

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        super().tearDown()

    def call(self, path, body=None, csrf=True):
        headers = {'Host': 'localhost:8000'}
        if body is not None:
            headers.update({'Content-Type': 'application/json', 'Origin': app.ORIGIN})
            if csrf:
                headers['X-CSRF-Token'] = self.csrf
        req = request.Request('http://127.0.0.1:%s%s' % (self.server.server_port, path),
                              data=json.dumps(body).encode() if body is not None else None, headers=headers)
        try:
            response = self.client.open(req)
        except error.HTTPError as exc:
            response = exc
        with response:
            return response.status, json.loads(response.read())

    def login(self):
        status, _ = self.call('/api/login', {'username': 'teacher', 'password': 'test-only password'})
        self.assertEqual(status, 200)
        self.csrf = self.call('/api/state')[1]['csrf']

    def test_authentication_and_csrf(self):
        self.assertEqual(self.call('/api/inbox')[0], 401)
        self.assertEqual(self.call('/api/login', {'username': 'teacher', 'password': 'wrong'})[0], 401)
        before = self.csrf
        self.login()
        self.assertNotEqual(before, self.csrf)
        self.assertEqual(self.call('/api/inbox')[0], 200)
        self.assertEqual(self.call('/api/settings', {'theme': 'dark'}, csrf=False)[0], 403)
        self.assertEqual(self.call('/api/settings', {'theme': 'dark'})[0], 200)
        self.assertEqual(self.call('/api/state')[1]['user']['theme'], 'dark')

    def test_rules_and_cross_user_isolation(self):
        self.login()
        self.assertEqual(self.call('/api/rules/save', rule())[0], 200)
        self.assertEqual(self.call('/api/rules/save', rule(label='INBOX'))[0], 400)
        self.assertEqual(self.call('/api/rules/save', rule('sender', 'principal', 20))[0], 400)
        with app.connect() as con:
            other = con.execute("INSERT INTO users(sub,email,name,username) VALUES('other','other@test.org','Other','other')").lastrowid
            rid = con.execute("INSERT INTO rules(uid,field,term,points) VALUES(?,'subject','private',99)", (other,)).lastrowid
        self.call('/api/rules/delete', {'id': rid})
        with app.connect() as con:
            self.assertIsNotNone(con.execute('SELECT id FROM rules WHERE id=?', (rid,)).fetchone())
        self.assertEqual(len(self.call('/api/inbox')[1]['rules']), 1)

    def test_password_changes_need_current_password_or_google_verification(self):
        self.login()
        fields = {'username': 'teacher', 'password': 'New app password 2026!'}
        self.assertEqual(self.call('/api/profile', fields)[0], 403)
        fields['current_password'] = 'test-only password'
        self.assertEqual(self.call('/api/profile', fields)[0], 200)
        self.csrf = self.call('/api/state')[1]['csrf']
        with app.connect() as con:
            con.execute('UPDATE sessions SET verified=? WHERE uid=?', (time.time(), self.uid))
        self.assertEqual(self.call('/api/profile', {'username': 'teacher', 'password': 'Another app password 2026!'})[0], 200)

    def test_live_username_availability(self):
        self.login()
        self.assertTrue(self.call('/api/username?value=My%20Name%20%F0%9F%8C%99')[1]['available'])
        with app.connect() as con:
            con.execute("INSERT INTO users(sub,email,name,username) VALUES('taken','taken@test.org','Taken','My Name')")
        self.assertFalse(self.call('/api/username?value=my%20name')[1]['available'])

    def test_reply_star_label_and_trash_actions(self):
        self.login()
        msg = message('Your OTP verification code is 123456.')
        with app.connect() as con:
            con.execute('INSERT INTO messages VALUES(?,?,?,?,?,?,?,?)', (self.uid, msg['id'], msg['subject'], msg['sender'], msg['sender_email'], msg['body'], msg['received'], json.dumps(msg['labels'])))
        self.assertEqual(app.load_messages(self.uid)[0]['category'], 'OTP & verification')
        self.assertEqual(app.load_messages(self.uid)[0]['score'], 0)
        calls = []
        def fake(token, path, method='GET', payload=None, **params):
            calls.append((path, payload))
            if path == '/messages/abc' and method == 'GET':
                return {'threadId': 'thread1', 'payload': {'headers': [
                    {'name': 'Reply-To', 'value': 'office@school.test'},
                    {'name': 'Subject', 'value': 'School update'},
                    {'name': 'Message-ID', 'value': '<original@school.test>'}]}}
            if path == '/labels':
                return {'labels': [{'id': 'Label_1', 'name': 'School', 'type': 'user'}]}
            return {'labelIds': ['INBOX', 'STARRED', 'Label_1']}
        with patch.object(app, 'access_token', return_value='fake'), patch.object(app, 'gmail', side_effect=fake):
            self.assertEqual(self.call('/api/reply-details?id=abc')[1]['recipient'], 'office@school.test')
            self.assertEqual(self.call('/api/message', {'id': 'abc', 'action': 'reply', 'text': 'Thank you.'})[0], 200)
            sent = next(payload for path, payload in calls if path == '/messages/send')
            from email import message_from_bytes
            reply = message_from_bytes(base64.urlsafe_b64decode(sent['raw']))
            self.assertEqual(reply['To'], 'office@school.test')
            self.assertEqual(reply['In-Reply-To'], '<original@school.test>')
            self.assertEqual(sent['threadId'], 'thread1')
            self.assertEqual(self.call('/api/message', {'id': 'abc', 'action': 'star', 'starred': True})[0], 200)
            self.assertEqual(self.call('/api/message', {'id': 'abc', 'action': 'label', 'label_id': 'Label_1'})[0], 200)
            self.assertEqual(self.call('/api/message', {'id': 'abc', 'action': 'label', 'label_id': 'NOT_ALLOWED'})[0], 400)
            self.assertEqual(self.call('/api/message', {'id': 'abc', 'action': 'trash'})[0], 200)
        self.assertEqual(app.load_messages(self.uid), [])

    def test_message_lookup_outside_cache_and_bulk_preview_snapshot(self):
        self.login()
        calls = []
        def fake(token, path, method='GET', payload=None, **params):
            calls.append((path, method))
            if path == '/messages':
                return {'messages': [{'id': 'abc'}, {'id': 'different'}]}
            if path.endswith('/trash'):
                return {}
            sender = 'principal@school.test' if path.endswith('abc') else 'other@school.test'
            return {'id': path.rsplit('/', 1)[-1], 'internalDate': '1793527200000', 'labelIds': ['INBOX'],
                    'payload': {'mimeType': 'text/plain', 'headers': [{'name': 'From', 'value': sender}, {'name': 'Subject', 'value': 'Specific mail'}],
                    'body': {'data': base64.urlsafe_b64encode(b'This is the original message.').decode()}}}
        with patch.object(app, 'access_token', return_value='fake'), patch.object(app, 'gmail', side_effect=fake):
            status, found = self.call('/api/mail?id=abc')
            self.assertEqual(status, 200)
            self.assertEqual(found['message']['id'], 'abc')
            status, preview = self.call('/api/bulk/preview', {'field': 'sender', 'term': 'principal@school.test'})
            self.assertEqual(status, 200)
            self.assertEqual(len(preview['messages']), 1)
            plan = preview['plan']
            self.assertEqual(self.call('/api/bulk/trash', {'plan': 'forged'})[0], 400)
            result = self.call('/api/bulk/trash', {'plan': plan})[1]
            self.assertEqual(result['moved'], 1)
            self.assertEqual(result['remaining'], 0)
            self.assertNotIn(('/messages/different/trash', 'POST'), calls)
            self.assertEqual(self.call('/api/bulk/trash', {'plan': plan})[1]['moved'], 0)

    def test_block_and_unblock_gmail_filter(self):
        self.login()
        scope = app.SCOPE + ' https://www.googleapis.com/auth/gmail.settings.basic'
        with app.connect() as con:
            con.execute('UPDATE users SET tokens=? WHERE id=?', (json.dumps({'access_token': 'fake', 'scope': scope}), self.uid))
        with patch.object(app, 'access_token', return_value='fake'), patch.object(app, 'protect', side_effect=lambda v, decrypt=False: v), patch.object(app, 'gmail', return_value={'id': 'filter123'}) as fake:
            status, result = self.call('/api/blocks', {'sender': 'ads@example.com'})
            self.assertEqual(status, 200)
            self.assertEqual(result['senders'], ['ads@example.com'])
            self.assertEqual(fake.call_args.args[3]['action']['addLabelIds'], ['TRASH'])
            self.call('/api/blocks', {'sender': 'ads@example.com'})
            self.assertEqual(fake.call_count, 1)
            self.assertEqual(self.call('/api/blocks', {'sender': 'ads@example.com', 'unblock': True})[1]['senders'], [])
            self.assertEqual(fake.call_args.args[2], 'DELETE')

    def test_block_listing_verifies_saved_and_shows_gmail_sender_filters(self):
        self.login()
        with app.connect() as con:
            con.execute('UPDATE users SET tokens=? WHERE id=?', (json.dumps({'scope': 'https://www.googleapis.com/auth/gmail.settings.basic'}), self.uid))
            con.execute('INSERT INTO blocked_senders VALUES(?,?,?)', (self.uid, 'active@test.org', 'ours'))
            con.execute('INSERT INTO blocked_senders VALUES(?,?,?)', (self.uid, 'removed@test.org', 'gone'))
        filters = {'filter': [
            {'id': 'ours', 'criteria': {'from': 'active@test.org'}, 'action': {'addLabelIds': ['TRASH']}},
            {'id': 'external', 'criteria': {'from': 'external@test.org'}, 'action': {'addLabelIds': ['TRASH']}},
            {'id': 'conditional', 'criteria': {'from': 'conditional@test.org', 'subject': 'special'}, 'action': {'addLabelIds': ['TRASH']}}]}
        with patch.object(app, 'protect', side_effect=lambda v, decrypt=False: v), patch.object(app, 'access_token', return_value='fake'), patch.object(app, 'gmail', return_value=filters):
            status, result = self.call('/api/blocks')
        self.assertEqual(status, 200)
        entries = {entry['sender']: entry for entry in result['entries']}
        self.assertEqual(entries['active@test.org']['status'], 'Active')
        self.assertEqual(entries['removed@test.org']['status'], 'Not active in Gmail')
        self.assertFalse(entries['external@test.org']['managed'])
        self.assertNotIn('conditional@test.org', entries)
        self.assertTrue(result['can_manage'])
        self.assertEqual(result['warning'], '')

    def test_block_listing_retains_saved_entries_when_permission_or_network_fails(self):
        self.login()
        with app.connect() as con:
            con.execute('INSERT INTO blocked_senders VALUES(?,?,?)', (self.uid, 'saved@test.org', 'saved'))
            con.execute('UPDATE users SET tokens=? WHERE id=?', (json.dumps({'scope': app.SCOPE}), self.uid))
        with patch.object(app, 'protect', side_effect=lambda v, decrypt=False: v):
            result = self.call('/api/blocks')[1]
        self.assertEqual(result['senders'], ['saved@test.org'])
        self.assertFalse(result['can_manage'])
        self.assertIn('permission', result['warning'])
        with app.connect() as con:
            con.execute('UPDATE users SET tokens=? WHERE id=?', (json.dumps({'scope': 'https://www.googleapis.com/auth/gmail.settings.basic'}), self.uid))
        with patch.object(app, 'protect', side_effect=lambda v, decrypt=False: v), patch.object(app, 'access_token', return_value='fake'), patch.object(app, 'gmail', side_effect=app.AppError('Network unavailable', 502)):
            result = self.call('/api/blocks')[1]
        self.assertEqual(result['senders'], ['saved@test.org'])
        self.assertEqual(result['entries'][0]['status'], 'Not verified')
        self.assertIn('Network', result['warning'])

    def test_oauth_state_rejection(self):
        self.assertEqual(self.call('/auth/callback?state=forged&code=fake')[0], 403)

    def test_read_status_and_disconnect_revoke_and_clear(self):
        self.login()
        msg = message()
        with app.connect() as con:
            con.execute('INSERT INTO messages VALUES(?,?,?,?,?,?,?,?)', (self.uid, msg['id'], msg['subject'], msg['sender'], msg['sender_email'], msg['body'], msg['received'], json.dumps(msg['labels'])))
            con.execute('UPDATE users SET tokens=? WHERE id=?', (json.dumps({'access_token': 'fake', 'refresh_token': 'fake-refresh'}), self.uid))
            con.execute("INSERT INTO rules(uid,field,term,points) VALUES(?,'subject','update',5)", (self.uid,))
        with patch.object(app, 'access_token', return_value='fake'), patch.object(app, 'gmail', return_value={'labelIds': ['INBOX']}) as modify:
            self.assertEqual(self.call('/api/message', {'id': 'abc', 'read': True})[0], 200)
            self.assertEqual(modify.call_args.args[3], {'removeLabelIds': ['UNREAD']})
        self.assertNotIn('UNREAD', app.load_messages(self.uid)[0]['labels'])
        with patch.object(app, 'protect', side_effect=lambda value, decrypt=False: value), patch.object(app, 'http_json', return_value={}) as revoke:
            self.assertEqual(self.call('/api/disconnect', {})[0], 200)
            self.assertTrue(revoke.call_args.args[0].endswith('/revoke'))
            self.assertEqual(revoke.call_args.args[2]['token'], 'fake-refresh')
        self.assertEqual(app.load_messages(self.uid), [])
        state = self.call('/api/state')[1]
        self.assertFalse(state['user']['connected'])
        self.assertEqual(state['user']['username'], 'teacher')
        self.assertEqual(len(self.call('/api/inbox')[1]['rules']), 1)

    def test_google_signup_callback_pkce_and_profile_setup(self):
        class NoRedirect(request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        jar = next(h.cookiejar for h in self.client.handlers if isinstance(h, request.HTTPCookieProcessor))
        self.client = request.build_opener(NoRedirect(), request.HTTPCookieProcessor(jar))
        cfg = {'client_id': 'test.apps.googleusercontent.com', 'client_secret': 'test-secret'}
        with patch.object(app, 'google_config', return_value=cfg):
            with self.assertRaises(error.HTTPError) as redirect:
                self.client.open(request.Request('http://127.0.0.1:%s/auth/google?mode=signup' % self.server.server_port, headers={'Host': 'localhost:8000'}))
        with redirect.exception as response:
            self.assertEqual(response.code, 302)
            params = parse.parse_qs(parse.urlparse(response.headers['Location']).query)
        self.assertEqual(params['code_challenge_method'], ['S256'])
        self.assertEqual(params['redirect_uri'], [app.REDIRECT])
        self.assertEqual(params['access_type'], ['offline'])
        def google_response(url, *args, **kwargs):
            if url.endswith('/token'):
                self.assertTrue(args[1]['code_verifier'])
                return {'access_token': 'fake-access', 'refresh_token': 'fake-refresh', 'scope': app.SCOPE, 'expires_in': 3600}
            return {'sub': 'brand-new-google-user', 'email': 'new@school.test', 'name': 'New Teacher', 'email_verified': True}
        callback = '/auth/callback?code=fake-code&state=' + params['state'][0]
        with patch.object(app, 'google_config', return_value=cfg), patch.object(app, 'http_json', side_effect=google_response), patch.object(app, 'protect', side_effect=lambda value, decrypt=False: value):
            with self.assertRaises(error.HTTPError) as returned:
                self.client.open(request.Request('http://127.0.0.1:%s%s' % (self.server.server_port, callback), headers={'Host': 'localhost:8000'}))
            with returned.exception as response:
                self.assertEqual(response.code, 302)
                self.assertEqual(response.headers['Location'], '/')
        status, state = self.call('/api/state')
        self.assertEqual(status, 200)
        self.assertEqual(state['user']['email'], 'new@school.test')
        self.assertIsNone(state['user']['username'])
        self.assertTrue(state['user']['connected'])
        self.csrf = state['csrf']
        self.assertEqual(self.call('/api/inbox')[0], 403)
        self.assertEqual(self.call('/api/profile', {'username': 'new-teacher', 'password': 'Separate app password 2026!'})[0], 200)
        self.csrf = self.call('/api/state')[1]['csrf']
        self.assertEqual(self.call('/api/inbox')[0], 200)
        self.assertEqual(self.call(callback)[0], 403)  # Single-use OAuth state.


if __name__ == '__main__':
    unittest.main()
