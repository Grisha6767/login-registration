def test_follow_user(logged_client, user2):
    r = logged_client.post('/api/follow/2')
    assert r.status_code == 200
    assert r.get_json()['following'] is True


def test_unfollow_user(logged_client, user2):
    logged_client.post('/api/follow/2')
    r = logged_client.post('/api/follow/2')
    assert r.get_json()['following'] is False


def test_follow_self(logged_client):
    r = logged_client.post('/api/follow/1')
    assert r.status_code == 400


def test_follow_nonexistent(logged_client):
    r = logged_client.post('/api/follow/9999')
    assert r.status_code == 404


def test_friends_when_mutual(logged_client, logged_client2):
    # alice → bob
    logged_client.post('/api/follow/2')
    # bob → alice
    logged_client2.post('/api/follow/1')

    # смотрим страницу друзей у alice
    r = logged_client.get('/users?tab=friends')
    assert 'bob' in r.get_data(as_text=True)


def test_following_list(logged_client, user2):
    # 1. Подписываемся
    r = logged_client.post('/api/follow/2')
    print("Статус follow:", r.status_code)
    print("Ответ:", r.get_json())
    assert r.status_code == 200, f"follow не сработал: {r.get_json()}"
    assert r.get_json()['following'] is True

    # 2. Проверяем, что подписка есть в БД
    with logged_client.application.app_context():
        from app import User
        alice = User.query.filter_by(username='alice').first()
        bob = User.query.filter_by(username='bob').first()
        print("Alice:", alice)
        print("Bob:", bob)
        print("Following у Alice:", [u.username for u in alice.following.all()])
        assert bob in alice.following.all(), "bob не в подписках alice"

    # 3. Смотрим HTML страницы
    r2 = logged_client.get('/users?tab=following')
    assert r2.status_code == 200
    html = r2.get_data(as_text=True)

    # 4. Ищем bob в разных вариантах
    print("Длина HTML:", len(html))
    print("'bob' в HTML:", 'bob' in html)
    print("'Bob' в HTML:", 'Bob' in html)
    print("Первый 500 символов body:")
    print(html[html.find('<body'):html.find('<body')+500])

    assert 'bob' in html