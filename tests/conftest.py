import os
import sys
import pytest

# Чтобы `import app` работал из корня проекта
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# ОБЯЗАТЕЛЬНО до импорта app — задаём тестовую БД и ключ
os.environ['SECRET_KEY'] = 'test-secret-key-' + 'x' * 40
os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
os.environ['DEBUG'] = 'False'
os.environ['SESSION_COOKIE_SECURE'] = 'False'

from app import app, db, User, Post, Message  # noqa: E402
from app import app, db, User, Post, Message, limiter
limiter.enabled = False


@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False  # отключаем CSRF для удобства тестов
    with app.test_client() as c:
        with app.app_context():
            db.drop_all()
            db.create_all()
            yield c
            db.session.remove()
            db.drop_all()


@pytest.fixture
def user(client):
    """Создаёт пользователя через API и возвращает его данные."""
    r = client.post('/api/register', json={
        'username': 'alice',
        'password': 'Password1'
    })
    assert r.status_code == 200
    return {'username': 'alice', 'password': 'Password1'}


@pytest.fixture
def user2(client):
    r = client.post('/api/register', json={
        'username': 'bob',
        'password': 'Password1'
    })
    assert r.status_code == 200
    return {'username': 'bob', 'password': 'Password1'}


def login(client, username, password):
    return client.post('/api/login', json={'username': username, 'password': password})


@pytest.fixture
def logged_client(client, user):
    """Клиент, уже залогиненный как alice."""
    r = login(client, user['username'], user['password'])
    assert r.status_code == 200
    return client


@pytest.fixture
def logged_client2(client, user2):
    """Второй клиент, залогиненный как bob (для проверки чужого доступа)."""
    client2 = app.test_client()
    r = client2.post('/api/login', json={'username': user2['username'], 'password': user2['password']})
    assert r.status_code == 200
    return client2