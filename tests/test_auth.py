def test_register_success(client):
    r = client.post('/api/register', json={
        'username': 'newuser',
        'password': 'StrongPass1'
    })
    assert r.status_code == 200
    assert r.get_json()['ok'] is True


def test_register_duplicate(client, user):
    r = client.post('/api/register', json={
        'username': user['username'],
        'password': 'AnotherPass1'
    })
    assert r.status_code == 409
    assert 'уже существует' in r.get_json()['message']


def test_register_short_password(client):
    r = client.post('/api/register', json={
        'username': 'shortpass',
        'password': 'abc'
    })
    assert r.status_code == 400
    assert '8 символов' in r.get_json()['message']


def test_register_password_no_digit(client):
    r = client.post('/api/register', json={
        'username': 'nodigit',
        'password': 'NoDigitsHere'
    })
    assert r.status_code == 400
    assert 'цифра' in r.get_json()['message'].lower()


def test_register_password_no_uppercase(client):
    r = client.post('/api/register', json={
        'username': 'nouppercase',
        'password': 'lowercase1'
    })
    assert r.status_code == 400
    assert 'заглавная' in r.get_json()['message'].lower()


def test_register_invalid_username(client):
    r = client.post('/api/register', json={
        'username': 'bad user!',
        'password': 'StrongPass1'
    })
    assert r.status_code == 400


def test_login_success(client, user):
    r = client.post('/api/login', json={
        'username': user['username'],
        'password': user['password']
    })
    assert r.status_code == 200
    data = r.get_json()
    assert data['ok'] is True
    assert 'redirect' in data


def test_login_wrong_password(client, user):
    r = client.post('/api/login', json={
        'username': user['username'],
        'password': 'WrongPass1'
    })
    assert r.status_code == 401
    assert 'Неверный пароль' in r.get_json()['message']


def test_login_no_user(client):
    r = client.post('/api/login', json={
        'username': 'ghost',
        'password': 'Password1'
    })
    assert r.status_code == 404
    assert 'не существует' in r.get_json()['message']


def test_logout(logged_client):
    r = logged_client.post('/api/logout')
    assert r.status_code == 200
    # после выхода профиль должен редиректить на логин
    r2 = logged_client.get('/profile')
    assert r2.status_code == 302