def test_csrf_protection_enabled():
    """Проверяем, что CSRF реально работает (без отключения в фикстуре)."""
    from app import app
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = True
    with app.test_client() as c:
        r = c.post('/api/login', json={'username': 'x', 'password': 'y'})
        # без токена — должно быть 400
        assert r.status_code == 400


def test_cannot_edit_others_post(logged_client, logged_client2):
    r = logged_client.post('/api/posts', json={'text': 'Пост alice'})
    post_id = int(r.get_json()['html'].split('data-id="')[1].split('"')[0])
    r2 = logged_client2.put(f'/api/posts/{post_id}', json={'text': 'Взлом'})
    assert r2.status_code == 403


def test_cannot_delete_others_post(logged_client, logged_client2):
    r = logged_client.post('/api/posts', json={'text': 'Пост alice'})
    post_id = int(r.get_json()['html'].split('data-id="')[1].split('"')[0])
    r2 = logged_client2.delete(f'/api/posts/{post_id}')
    assert r2.status_code == 403


def test_anonymous_cannot_create_post(client):
    r = client.post('/api/posts', json={'text': 'анон'})
    assert r.status_code == 401


def test_anonymous_redirected_from_profile(client):
    r = client.get('/profile')
    assert r.status_code == 302


def test_anonymous_redirected_from_wall(client):
    r = client.get('/wall')
    assert r.status_code == 302


def test_anonymous_redirected_from_messages(client):
    r = client.get('/messages')
    assert r.status_code == 302


def test_security_headers(logged_client):
    r = logged_client.get('/wall')
    assert r.headers['X-Frame-Options'] == 'SAMEORIGIN'
    assert r.headers['X-Content-Type-Options'] == 'nosniff'
    assert 'Content-Security-Policy' in r.headers
    assert 'Referrer-Policy' in r.headers


def test_sql_injection_in_search(logged_client):
    """Классическая SQL-инъекция не должна ничего сломать."""
    payload = "' OR 1=1; DROP TABLE user; --"
    r = logged_client.get(f'/search?q={payload}')
    # не должно быть 500
    assert r.status_code == 200
    # таблица user всё ещё существует (проверяем логином)
    r2 = logged_client.get('/wall')
    assert r2.status_code == 200


def test_xss_in_post(logged_client):
    """XSS-попытка — должна быть заэкранирована."""
    payload = '<script>alert(1)</script>'
    r = logged_client.post('/api/posts', json={'text': payload})
    assert r.status_code == 200
    html = r.get_json()['html']
    # <script> не должен быть "живым"
    assert '<script>alert(1)</script>' not in html
    # но текст сохранён и заэкранирован
    assert '&lt;script&gt;' in html


def test_password_not_returned(logged_client):
    """Проверяем, что хеш пароля нигде не отдаётся."""
    r = logged_client.get('/profile')
    text = r.get_data(as_text=True)
    assert 'password_hash' not in text
    assert 'pbkdf2:' not in text
    assert 'scrypt:' not in text