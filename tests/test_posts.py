def test_create_post(logged_client):
    r = logged_client.post('/api/posts', json={'text': 'Мой первый пост'})
    assert r.status_code == 200
    data = r.get_json()
    assert data['ok'] is True
    assert 'Мой первый пост' in data['html']


def test_create_empty_post(logged_client):
    r = logged_client.post('/api/posts', json={'text': '   '})
    assert r.status_code == 400


def test_create_post_too_long(logged_client):
    r = logged_client.post('/api/posts', json={'text': 'x' * 1001})
    assert r.status_code == 400


def test_create_post_unauthorized(client):
    r = client.post('/api/posts', json={'text': 'anonym'})
    assert r.status_code == 401


def test_edit_own_post(logged_client):
    r = logged_client.post('/api/posts', json={'text': 'Старый текст'})
    post_id = int(r.get_json()['html'].split('data-id="')[1].split('"')[0])

    r2 = logged_client.put(f'/api/posts/{post_id}', json={'text': 'Новый текст'})
    assert r2.status_code == 200

    # проверяем, что текст обновился
    r3 = logged_client.get('/wall')
    assert 'Новый текст' in r3.get_data(as_text=True)


def test_edit_someone_elses_post(logged_client, logged_client2):
    r = logged_client.post('/api/posts', json={'text': 'Пост alice'})
    post_id = int(r.get_json()['html'].split('data-id="')[1].split('"')[0])

    # bob пытается редактировать пост alice
    r2 = logged_client2.put(f'/api/posts/{post_id}', json={'text': 'Взлом!'})
    assert r2.status_code == 403


def test_delete_own_post(logged_client):
    r = logged_client.post('/api/posts', json={'text': 'Удалить меня'})
    post_id = int(r.get_json()['html'].split('data-id="')[1].split('"')[0])

    r2 = logged_client.delete(f'/api/posts/{post_id}')
    assert r2.status_code == 200


def test_delete_someone_elses_post(logged_client, logged_client2):
    r = logged_client.post('/api/posts', json={'text': 'Пост alice'})
    post_id = int(r.get_json()['html'].split('data-id="')[1].split('"')[0])

    r2 = logged_client2.delete(f'/api/posts/{post_id}')
    assert r2.status_code == 403


def test_like_toggle(logged_client):
    r = logged_client.post('/api/posts', json={'text': 'Лайкни меня'})
    post_id = int(r.get_json()['html'].split('data-id="')[1].split('"')[0])

    r1 = logged_client.post(f'/api/posts/{post_id}/like')
    assert r1.get_json()['liked'] is True
    assert r1.get_json()['count'] == 1

    r2 = logged_client.post(f'/api/posts/{post_id}/like')
    assert r2.get_json()['liked'] is False
    assert r2.get_json()['count'] == 0


def test_comment_add(logged_client):
    r = logged_client.post('/api/posts', json={'text': 'Пост с комментом'})
    post_id = int(r.get_json()['html'].split('data-id="')[1].split('"')[0])

    r2 = logged_client.post(
        f'/api/posts/{post_id}/comments',
        json={'text': 'Первый!'}
    )
    assert r2.status_code == 200
    assert 'Первый!' in r2.get_json()['html']


def test_comment_too_long(logged_client):
    r = logged_client.post('/api/posts', json={'text': 'Пост'})
    post_id = int(r.get_json()['html'].split('data-id="')[1].split('"')[0])

    r2 = logged_client.post(
        f'/api/posts/{post_id}/comments',
        json={'text': 'x' * 501}
    )
    assert r2.status_code == 400


def test_search_finds_post(logged_client):
    logged_client.post('/api/posts', json={'text': 'Уникальное слово зюйдвестка'})
    r = logged_client.get('/search?q=зюйдвестка')
    assert r.status_code == 200
    assert 'зюйдвестка' in r.get_data(as_text=True)


def test_search_not_found(logged_client):
    r = logged_client.get('/search?q=такоготочнонет12345')
    assert 'Ничего не найдено' in r.get_data(as_text=True)