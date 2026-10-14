import io


def test_view_own_profile(logged_client):
    r = logged_client.get('/profile')
    assert r.status_code == 200
    assert 'alice' in r.get_data(as_text=True)


def test_view_other_profile(logged_client, user2):
    r = logged_client.get('/user/2')
    assert r.status_code == 200
    assert 'bob' in r.get_data(as_text=True)


def test_view_nonexistent_profile(logged_client):
    r = logged_client.get('/user/9999')
    assert r.status_code == 404


def test_update_profile(logged_client):
    r = logged_client.post('/api/profile/update', json={
        'username': 'alice_new',
        'bio': 'Привет, я обновился!',
        'password': ''
    })
    assert r.status_code == 200

    r2 = logged_client.get('/profile')
    assert 'alice_new' in r2.get_data(as_text=True)
    assert 'обновился' in r2.get_data(as_text=True)


def test_update_profile_duplicate_username(logged_client, user2):
    r = logged_client.post('/api/profile/update', json={
        'username': 'bob',  # уже занят
        'bio': '',
        'password': ''
    })
    assert r.status_code == 409


def test_update_profile_weak_password(logged_client):
    r = logged_client.post('/api/profile/update', json={
        'username': 'alice',
        'bio': '',
        'password': 'abc'
    })
    assert r.status_code == 400


def test_upload_avatar(logged_client, tmp_path):
    # создаём фейковую PNG-картинку через Pillow
    from PIL import Image
    img = Image.new('RGB', (100, 100), color='blue')
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)

    r = logged_client.post('/api/profile/avatar', data={
        'avatar': (buf, 'test.png')
    }, content_type='multipart/form-data')

    assert r.status_code == 200
    assert r.get_json()['ok'] is True


def test_upload_avatar_wrong_format(logged_client):
    r = logged_client.post('/api/profile/avatar', data={
        'avatar': (io.BytesIO(b'not an image'), 'fake.txt')
    }, content_type='multipart/form-data')
    assert r.status_code == 400


def test_upload_fake_png(logged_client):
    """Файл с .png, но внутри не картинка — должен быть отклонён."""
    r = logged_client.post('/api/profile/avatar', data={
        'avatar': (io.BytesIO(b'this is not a png'), 'evil.png')
    }, content_type='multipart/form-data')
    assert r.status_code == 400