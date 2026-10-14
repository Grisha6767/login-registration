import os
import uuid
import re
from datetime import datetime

from dotenv import load_dotenv
from flask import (
    Flask, render_template, render_template_string, request,
    jsonify, session, redirect, url_for, send_from_directory, abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit, join_room
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import or_, and_
from PIL import Image

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
if not app.config['SECRET_KEY'] or len(app.config['SECRET_KEY']) < 32:
    raise RuntimeError('SECRET_KEY must be set in .env and be at least 32 chars')

# Безопасные cookie
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.getenv('SESSION_COOKIE_SECURE', 'False') == 'True',
    PERMANENT_SESSION_LIFETIME=1800,
)

# Загрузки
UPLOAD_FOLDER = os.path.join(app.root_path, os.getenv('UPLOAD_FOLDER', 'uploads'))
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_CONTENT_LENGTH_MB', '5')) * 1024 * 1024

ALLOWED_EXT = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app,
                  default_limits=["1000 per day", "200 per hour"],
                  storage_uri="memory://")
socketio = SocketIO(app, cors_allowed_origins=[
    "http://localhost:5000", "http://127.0.0.1:5000"
], async_mode='threading')


# ============================================================
# МОДЕЛИ
# ============================================================

followers = db.Table(
    'followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('following_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    bio = db.Column(db.String(500), default='')
    avatar = db.Column(db.String(200), default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    posts = db.relationship('Post', backref='author', lazy=True,
                            cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='author', lazy=True,
                               cascade='all, delete-orphan')

    following = db.relationship(
        'User', secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.following_id == id),
        backref=db.backref('followers_rel', lazy='dynamic'),
        lazy='dynamic'
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def avatar_url(self):
        if self.avatar:
            return url_for('uploaded_file', filename=self.avatar)
        return ''

    def is_following(self, other):
        return self.following.filter(followers.c.following_id == other.id).count() > 0

    def is_friend(self, other):
        return self.is_following(other) and other.is_following(self)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(1000), nullable=False)
    image = db.Column(db.String(200), default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    likes = db.relationship('Like', backref='post', lazy=True,
                            cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='post', lazy=True,
                               cascade='all, delete-orphan',
                               order_by='Comment.created_at')

    @property
    def image_url(self):
        if self.image:
            return url_for('uploaded_file', filename=self.image)
        return ''

    def likes_count(self):
        return len(self.likes)

    def liked_by(self, user):
        if not user:
            return False
        return any(l.user_id == user.id for l in self.likes)


class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='unique_like'),)


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(1000), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    is_read = db.Column(db.Boolean, default=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    sender = db.relationship('User', foreign_keys=[sender_id],
                             backref=db.backref('sent_messages', lazy='dynamic'))
    recipient = db.relationship('User', foreign_keys=[recipient_id],
                                backref=db.backref('received_messages', lazy='dynamic'))


with app.app_context():
    db.create_all()


# ============================================================
# БЕЗОПАСНОСТЬ — HEADERS
# ============================================================

@app.after_request
def set_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=()'
    # CSP — только свои ресурсы + CDN socket.io
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "connect-src 'self' ws: wss:; "
        "font-src 'self'; "
        "frame-ancestors 'self'"
    )
    return response


# ============================================================
# ХЕЛПЕРЫ
# ============================================================

def current_user():
    if 'user_id' not in session:
        return None
    return User.query.get(session['user_id'])


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT


def save_image(file):
    """Сохраняет файл как изображение с проверкой через Pillow."""
    if not file or not file.filename:
        raise ValueError('Файл не выбран')
    if not allowed_file(file.filename):
        raise ValueError('Только png/jpg/jpeg/gif/webp')

    ext = file.filename.rsplit('.', 1)[1].lower()
    filename = f"{uuid.uuid4().hex}.{ext}"
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(path)

    try:
        img = Image.open(path)
        img.verify()  # реальная проверка, что это картинка
        img = Image.open(path).convert('RGB')
        img.thumbnail((1000, 1000))
        img.save(path, optimize=True, quality=85)
    except Exception:
        try: os.remove(path)
        except OSError: pass
        raise ValueError('Файл не является изображением')
    return filename


def validate_password(password):
    if len(password) < 8:
        return False, 'Пароль минимум 8 символов'
    if not re.search(r'[A-ZА-Я]', password):
        return False, 'Нужна хотя бы одна заглавная буква'
    if not re.search(r'\d', password):
        return False, 'Нужна хотя бы одна цифра'
    return True, ''


def validate_username(username):
    if len(username) < 3 or len(username) > 30:
        return False, 'Логин 3–30 символов'
    if not re.match(r'^[A-Za-z0-9_]+$', username):
        return False, 'Только латиница, цифры и _'
    return True, ''


def get_dialogs(me):
    msgs = (Message.query
            .filter(or_(Message.sender_id == me.id, Message.recipient_id == me.id))
            .order_by(Message.created_at.desc()).all())
    dialogs = {}
    for m in msgs:
        other_id = m.recipient_id if m.sender_id == me.id else m.sender_id
        if other_id not in dialogs:
            other = User.query.get(other_id)
            if other:
                dialogs[other_id] = {
                    'user': other,
                    'last': m,
                    'unread': Message.query.filter_by(
                        sender_id=other_id, recipient_id=me.id, is_read=False).count()
                }
    return list(dialogs.values())


def get_conversation(me, other):
    return (Message.query
            .filter(or_(
                and_(Message.sender_id == me.id, Message.recipient_id == other.id),
                and_(Message.sender_id == other.id, Message.recipient_id == me.id)
            ))
            .order_by(Message.created_at.asc()).all())


def _msg_html(m, me):
    return render_template_string("""
        <div class="msg-row {% if m.sender_id == me.id %}me{% endif %}" data-id="{{ m.id }}">
            <div class="msg-bubble">{{ m.text }}</div>
            <div class="msg-time">{{ m.created_at.strftime('%H:%M') }}</div>
        </div>
    """, m=m, me=me)


# ============================================================
# CSS
# ============================================================

BASE_STYLE = """
<style>
    * { box-sizing: border-box; }
    body { font-family: -apple-system, Arial, sans-serif; background: #f0f2f5;
           margin: 0; padding: 30px 15px; color: #222; }
    .container { max-width: 720px; margin: 0 auto; }
    .card { background: #fff; padding: 30px 40px; border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.08); }
    .topbar { display: flex; justify-content: space-between; align-items: center;
              background: #fff; padding: 12px 20px; border-radius: 10px;
              box-shadow: 0 2px 10px rgba(0,0,0,0.05); margin-bottom: 20px;
              flex-wrap: wrap; gap: 8px; }
    .topbar h2 { margin: 0; font-size: 20px; }
    .topbar a { color: #007bff; text-decoration: none; margin-left: 15px; font-size: 14px; }
    .topbar a:hover { text-decoration: underline; }

    .avatar, .avatar-sm, .avatar-lg { border-radius: 50%; background: #007bff;
        color: #fff; font-weight: bold; display: flex; justify-content: center;
        align-items: center; text-transform: uppercase; overflow: hidden;
        flex-shrink: 0; text-decoration: none; }
    .avatar { width: 80px; height: 80px; font-size: 36px; }
    .avatar-lg { width: 110px; height: 110px; font-size: 48px; }
    .avatar-sm { width: 45px; height: 45px; font-size: 20px; }
    .avatar img, .avatar-sm img, .avatar-lg img { width: 100%; height: 100%; object-fit: cover; }

    h2 { margin: 0 0 8px; }
    .subtitle { color: #666; margin-bottom: 20px; font-size: 14px; }
    .info { text-align: left; background: #f8f9fa; border-radius: 8px;
            padding: 15px 20px; margin-bottom: 20px; }
    .info-row { display: flex; justify-content: space-between; padding: 8px 0;
                border-bottom: 1px solid #e9ecef; }
    .info-row:last-child { border-bottom: none; }
    .label { color: #666; }
    .value { font-weight: bold; color: #333; text-align: right; max-width: 60%; }
    .bio-block { text-align: left; background: #fff8e1; border-left: 4px solid #ffc107;
                 padding: 12px 15px; border-radius: 6px; margin-bottom: 20px;
                 color: #555; font-size: 14px; white-space: pre-wrap; }

    .user-row { display: flex; align-items: center; background: #fff;
                padding: 14px 18px; border-radius: 10px; margin-bottom: 10px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.05);
                transition: transform 0.15s; }
    .user-row:hover { transform: translateX(4px); }
    .user-row .info { flex: 1; background: transparent; padding: 0; margin: 0; min-width: 0; }
    .name { font-weight: bold; font-size: 16px; }
    .name a { color: #222; text-decoration: none; }
    .name a:hover { text-decoration: underline; }
    .bio { color: #777; font-size: 13px; margin-top: 3px; overflow: hidden;
           text-overflow: ellipsis; white-space: nowrap; }
    .badge { display: inline-block; font-size: 11px; padding: 3px 8px;
             border-radius: 10px; color: #fff; margin-left: 6px; vertical-align: middle; }
    .me-badge      { background: #28a745; }
    .friend-badge  { background: #17a2b8; }
    .following-badge { background: #6c757d; }

    label { display: block; margin-top: 15px; color: #555; font-size: 14px; }
    input[type=text], input[type=password], textarea {
        width: 100%; padding: 10px; margin-top: 5px;
        border: 1px solid #ccc; border-radius: 6px;
        font-family: inherit; font-size: 14px; }
    textarea { resize: vertical; min-height: 80px; }
    .hint { color: #888; font-size: 12px; margin-top: 5px; }

    .btn { display: inline-block; padding: 8px 16px; border-radius: 6px;
           text-decoration: none; font-size: 14px; border: none;
           cursor: pointer; color: #fff; font-family: inherit;
           line-height: 1.4; }
    .btn-sm { padding: 5px 12px; font-size: 13px; }
    .btn-block { display: block; width: 100%; padding: 12px; margin-top: 12px;
                 text-align: center; }
    .btn-primary   { background: #007bff; }
    .btn-success   { background: #28a745; }
    .btn-secondary { background: #6c757d; }
    .btn-danger    { background: #dc3545; }
    .btn-warning   { background: #ffc107; color: #333; }
    .btn:hover { opacity: 0.9; }

    .msg { text-align: center; margin-top: 15px; font-size: 14px; }
    .success { color: #28a745; font-weight: bold; }
    .error   { color: #dc3545; }
    .center { text-align: center; }
    .muted { color: #888; font-size: 13px; }

    .composer { background: #fff; border-radius: 12px; padding: 18px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.06); margin-bottom: 20px;
                display: flex; gap: 12px; }
    .composer form { flex: 1; display: flex; flex-direction: column; min-width: 0; }
    .composer textarea { min-height: 70px; margin: 0; font-size: 15px; }
    .composer-actions { display: flex; justify-content: space-between;
                        align-items: center; margin-top: 10px; gap: 8px;
                        flex-wrap: wrap; }
    .counter { color: #888; font-size: 13px; }
    .counter.warn { color: #dc3545; font-weight: bold; }

    .post { background: #fff; border-radius: 12px; padding: 18px 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05); margin-bottom: 12px;
            display: flex; gap: 12px; }
    .post-body { flex: 1; min-width: 0; }
    .post-header { display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; }
    .post-author { font-weight: bold; color: #222; text-decoration: none; }
    .post-author:hover { text-decoration: underline; }
    .post-time { color: #999; font-size: 12px; }
    .post-text { margin-top: 6px; color: #333; font-size: 15px;
                 white-space: pre-wrap; word-wrap: break-word; }
    .post-image { margin-top: 10px; max-width: 100%; border-radius: 8px;
                  border: 1px solid #eee; display: block; max-height: 500px;
                  object-fit: contain; }
    .post-actions { display: flex; gap: 14px; margin-top: 10px;
                    align-items: center; font-size: 14px; color: #666;
                    flex-wrap: wrap; }
    .post-actions button, .post-actions a {
        background: none; border: none; cursor: pointer; color: #666;
        font-size: 14px; padding: 4px 6px; border-radius: 4px;
        text-decoration: none; font-family: inherit; }
    .post-actions button:hover, .post-actions a:hover { background: #f0f2f5; }
    .like-btn.liked { color: #e0245e; font-weight: bold; }
    .edited-mark { font-size: 11px; color: #999; font-style: italic; margin-left: 4px; }

    .comments { margin-top: 12px; padding-top: 10px; border-top: 1px solid #eee; }
    .comment { display: flex; gap: 8px; margin-top: 8px; }
    .comment-body { flex: 1; background: #f8f9fa; padding: 8px 12px;
                    border-radius: 8px; font-size: 14px; }
    .comment-author { font-weight: bold; color: #222;
                      text-decoration: none; font-size: 13px; }
    .comment-author:hover { text-decoration: underline; }
    .comment-text { margin-top: 3px; color: #333; word-wrap: break-word; }
    .comment-form { display: flex; gap: 8px; margin-top: 10px; }
    .comment-form input { margin: 0; flex: 1; }
    .empty { text-align: center; color: #888; padding: 40px 0; }

    .search-box { background: #fff; border-radius: 10px; padding: 12px 16px;
                  box-shadow: 0 2px 10px rgba(0,0,0,0.05); margin-bottom: 20px;
                  display: flex; gap: 10px; }
    .search-box input { margin: 0; flex: 1; }

    .tabs { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
    .tabs a { padding: 8px 16px; background: #fff; border-radius: 8px;
              text-decoration: none; color: #333; font-size: 14px;
              box-shadow: 0 1px 4px rgba(0,0,0,0.05); }
    .tabs a.active { background: #007bff; color: #fff; }

    .unread { background: #dc3545; color: #fff; font-size: 11px;
              border-radius: 10px; padding: 2px 7px; font-weight: bold;
              margin-left: 4px; }
</style>
"""

# JS-хелпер для CSRF в fetch
CSRF_JS = """
<script>
    function getCSRF() {
        const m = document.querySelector('meta[name="csrf-token"]');
        return m ? m.content : '';
    }
    const _origFetch = window.fetch;
    window.fetch = function(url, opts) {
        opts = opts || {};
        opts.headers = opts.headers || {};
        if (typeof opts.headers === 'object' && !(opts.headers instanceof Headers)) {
            opts.headers['X-CSRFToken'] = getCSRF();
        }
        return _origFetch(url, opts);
    };
</script>
"""

CSRF_META = '<meta name="csrf-token" content="{{ csrf_token() }}">'


# ============================================================
# ШАБЛОНЫ
# ============================================================

WALL_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    """ + CSRF_META + """
    <title>Стена</title>
    """ + BASE_STYLE + CSRF_JS + """
</head>
<body>
    <div class="container">
        <div class="topbar">
            <h2>📰 Стена</h2>
            <div>
                <a href="/wall?scope=following">Подписки</a>
                <a href="/users">Люди</a>
                <a href="/messages">Сообщения{% if unread_total %}<span class="unread">{{ unread_total }}</span>{% endif %}</a>
                <a href="/profile">Профиль</a>
            </div>
        </div>

        <form class="search-box" method="GET" action="/search">
            <input type="text" name="q" placeholder="Поиск по постам...">
            <button type="submit" class="btn btn-primary">Найти</button>
        </form>

        <div class="composer">
            <div class="avatar-sm">
                {% if me.avatar %}<img src="{{ me.avatar_url }}" alt="">
                {% else %}{{ me.username[0] }}{% endif %}
            </div>
            <form id="postForm" enctype="multipart/form-data">
                <textarea id="postText" maxlength="1000"
                          placeholder="Что нового, {{ me.username }}?"></textarea>
                <div class="composer-actions">
                    <div style="display:flex; align-items:center; gap:8px;">
                        <label for="postImage" class="btn btn-secondary btn-sm"
                               style="margin:0; cursor:pointer;">📷 Картинка</label>
                        <input type="file" id="postImage" name="image"
                               accept="image/*" style="display:none;">
                        <span id="imageName" class="muted"></span>
                    </div>
                    <div style="display:flex; align-items:center; gap:12px;">
                        <span id="counter" class="counter">0 / 1000</span>
                        <button type="submit" class="btn btn-primary">Опубликовать</button>
                    </div>
                </div>
            </form>
        </div>

        <p id="message" class="msg"></p>

        <div id="posts">
            {% if posts %}
                {% for post in posts %}{% include '__post.html' %}{% endfor %}
            {% else %}
                <div class="empty">Пока ни одного поста. Будь первым! ✨</div>
            {% endif %}
        </div>
    </div>

    <script>
        const form = document.getElementById('postForm');
        const textEl = document.getElementById('postText');
        const counter = document.getElementById('counter');
        const msgEl = document.getElementById('message');
        const imageInput = document.getElementById('postImage');
        const imageName = document.getElementById('imageName');

        textEl.addEventListener('input', () => {
            const len = textEl.value.length;
            counter.textContent = len + ' / 1000';
            counter.classList.toggle('warn', len > 950);
        });
        imageInput.addEventListener('change', () => {
            imageName.textContent = imageInput.files.length
                ? imageInput.files[0].name : '';
        });

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            const text = textEl.value.trim();
            if (!text) return;

            const fd = new FormData();
            fd.append('text', text);
            if (imageInput.files.length) fd.append('image', imageInput.files[0]);

            msgEl.textContent = '';
            msgEl.className = 'msg';
            try {
                const r = await fetch('/api/posts', { method: 'POST', body: fd });
                const data = await r.json();
                if (data.ok) {
                    const empty = document.querySelector('.empty');
                    if (empty) empty.remove();
                    document.getElementById('posts')
                        .insertAdjacentHTML('afterbegin', data.html);
                    textEl.value = ''; imageInput.value = '';
                    imageName.textContent = '';
                    counter.textContent = '0 / 1000';
                    counter.classList.remove('warn');
                    bindPostEvents();
                } else {
                    msgEl.textContent = data.message;
                    msgEl.classList.add('error');
                }
            } catch {
                msgEl.textContent = 'Ошибка соединения';
                msgEl.classList.add('error');
            }
        });

        function bindPostEvents() {
            document.querySelectorAll('.like-btn').forEach(btn => {
                if (btn.dataset.bound) return;
                btn.dataset.bound = '1';
                btn.addEventListener('click', async () => {
                    const r = await fetch('/api/posts/' + btn.dataset.id + '/like',
                                          { method: 'POST' });
                    const data = await r.json();
                    if (data.ok) {
                        btn.classList.toggle('liked', data.liked);
                        btn.querySelector('.like-count').textContent = data.count;
                    }
                });
            });

            document.querySelectorAll('.comment-form').forEach(f => {
                if (f.dataset.bound) return;
                f.dataset.bound = '1';
                f.addEventListener('submit', async (e) => {
                    e.preventDefault();
                    const input = f.querySelector('input');
                    const text = input.value.trim();
                    if (!text) return;
                    const r = await fetch('/api/posts/' + f.dataset.id + '/comments', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ text })
                    });
                    const data = await r.json();
                    if (data.ok) {
                        f.parentElement.querySelector('.comments-list')
                            .insertAdjacentHTML('beforeend', data.html);
                        input.value = '';
                        const cnt = f.closest('.post').querySelector('.comments-count');
                        if (cnt) cnt.textContent = data.total;
                    }
                });
            });

            document.querySelectorAll('.delete-post').forEach(btn => {
                if (btn.dataset.bound) return;
                btn.dataset.bound = '1';
                btn.addEventListener('click', async () => {
                    if (!confirm('Удалить пост?')) return;
                    const r = await fetch('/api/posts/' + btn.dataset.id,
                                          { method: 'DELETE' });
                    const data = await r.json();
                    if (data.ok) btn.closest('.post').remove();
                });
            });

            document.querySelectorAll('.edit-post').forEach(btn => {
                if (btn.dataset.bound) return;
                btn.dataset.bound = '1';
                btn.addEventListener('click', async () => {
                    const postEl = btn.closest('.post');
                    const textEl2 = postEl.querySelector('.post-text');
                    const oldText = textEl2.textContent;
                    const newText = prompt('Редактировать пост:', oldText);
                    if (newText === null) return;
                    const trimmed = newText.trim();
                    if (!trimmed || trimmed === oldText) return;
                    const r = await fetch('/api/posts/' + btn.dataset.id, {
                        method: 'PUT',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ text: trimmed })
                    });
                    const data = await r.json();
                    if (data.ok) {
                        textEl2.textContent = trimmed;
                        if (!postEl.querySelector('.edited-mark')) {
                            const mark = document.createElement('span');
                            mark.className = 'edited-mark';
                            mark.textContent = '(изменено)';
                            postEl.querySelector('.post-time')
                                .insertAdjacentElement('afterend', mark);
                        }
                    } else alert(data.message);
                });
            });
        }
        bindPostEvents();
    </script>
</body>
</html>
"""


SEARCH_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    """ + CSRF_META + """
    <title>Поиск</title>
    """ + BASE_STYLE + CSRF_JS + """
</head>
<body>
    <div class="container">
        <div class="topbar">
            <h2>🔍 Поиск</h2>
            <div>
                <a href="/wall">Стена</a>
                <a href="/messages">Сообщения{% if unread_total %}<span class="unread">{{ unread_total }}</span>{% endif %}</a>
                <a href="/profile">Профиль</a>
            </div>
        </div>
        <form class="search-box" method="GET" action="/search">
            <input type="text" name="q" placeholder="Поиск по постам..."
                   value="{{ q }}" autofocus>
            <button type="submit" class="btn btn-primary">Найти</button>
        </form>
        {% if q %}
            <p class="muted" style="margin: 0 0 12px;">
                {% if posts %}Найдено: {{ posts|length }}
                {% else %}Ничего не найдено по запросу «{{ q }}»{% endif %}
            </p>
        {% endif %}
        <div id="posts">
            {% for post in posts %}{% include '__post.html' %}{% endfor %}
        </div>
    </div>
    <script>
        document.querySelectorAll('.like-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                const r = await fetch('/api/posts/' + btn.dataset.id + '/like',
                                      { method: 'POST' });
                const data = await r.json();
                if (data.ok) {
                    btn.classList.toggle('liked', data.liked);
                    btn.querySelector('.like-count').textContent = data.count;
                }
            });
        });
    </script>
</body>
</html>
"""


USER_VIEW_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    """ + CSRF_META + """
    <title>Профиль {{ user.username }}</title>
    """ + BASE_STYLE + CSRF_JS + """
</head>
<body>
    <div class="container">
        <div class="card center">
            <div class="avatar-lg" style="margin: 0 auto 20px;">
                {% if user.avatar %}<img src="{{ user.avatar_url }}" alt="">
                {% else %}{{ user.username[0] }}{% endif %}
            </div>
            <h2>{{ user.username }}</h2>
            <p class="subtitle">
                {% if is_me %}Это ваш профиль
                {% elif is_friend %}🤝 Вы друзья
                {% elif i_follow %}Вы подписаны
                {% elif follows_me %}Подписан(а) на вас
                {% else %}Профиль пользователя{% endif %}
            </p>
            {% if user.bio %}<div class="bio-block">{{ user.bio }}</div>{% endif %}
            <div class="info">
                <div class="info-row"><span class="label">Постов</span>
                    <span class="value">{{ user.posts|length }}</span></div>
                <div class="info-row"><span class="label">Подписчиков</span>
                    <span class="value">{{ followers_count }}</span></div>
                <div class="info-row"><span class="label">Подписок</span>
                    <span class="value">{{ following_count }}</span></div>
                <div class="info-row"><span class="label">Дата регистрации</span>
                    <span class="value">{{ user.created_at.strftime('%d.%m.%Y') }}</span></div>
            </div>
            {% if not is_me %}
                <button id="followBtn"
                        class="btn {% if i_follow %}btn-secondary{% else %}btn-primary{% endif %}"
                        data-id="{{ user.id }}" data-following="{{ 1 if i_follow else 0 }}">
                    {% if i_follow %}Отписаться{% else %}Подписаться{% endif %}
                </button>
                <a href="/messages/{{ user.id }}" class="btn btn-success">💬 Написать</a>
            {% else %}
                <a href="/profile/edit" class="btn btn-primary">Редактировать</a>
            {% endif %}
            <a href="/wall" class="btn btn-success">На стену</a>
            <a href="/users" class="btn btn-secondary">Ко всем</a>

            <h3 style="margin-top: 30px; text-align: left;">Посты</h3>
            <div style="text-align: left;">
                {% if posts %}
                    {% for post in posts %}{% include '__post.html' %}{% endfor %}
                {% else %}<p class="muted">Нет постов.</p>{% endif %}
            </div>
        </div>
    </div>
    <script>
        const fbtn = document.getElementById('followBtn');
        if (fbtn) fbtn.addEventListener('click', async () => {
            const r = await fetch('/api/follow/' + fbtn.dataset.id, { method: 'POST' });
            const data = await r.json();
            if (data.ok) window.location.reload();
        });
        document.querySelectorAll('.like-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                const r = await fetch('/api/posts/' + btn.dataset.id + '/like',
                                      { method: 'POST' });
                const data = await r.json();
                if (data.ok) {
                    btn.classList.toggle('liked', data.liked);
                    btn.querySelector('.like-count').textContent = data.count;
                }
            });
        });
    </script>
</body>
</html>
"""


USERS_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    """ + CSRF_META + """
    <title>Пользователи</title>
    """ + BASE_STYLE + CSRF_JS + """
</head>
<body>
    <div class="container">
        <div class="topbar">
            <h2>Люди</h2>
            <div>
                <a href="/wall">Стена</a>
                <a href="/messages">Сообщения{% if unread_total %}<span class="unread">{{ unread_total }}</span>{% endif %}</a>
                <a href="/profile">Профиль</a>
            </div>
        </div>
        <div class="tabs">
            <a href="/users" class="{{ 'active' if tab == 'all' }}">Все</a>
            <a href="/users?tab=following" class="{{ 'active' if tab == 'following' }}">Подписки</a>
            <a href="/users?tab=followers" class="{{ 'active' if tab == 'followers' }}">Подписчики</a>
            <a href="/users?tab=friends" class="{{ 'active' if tab == 'friends' }}">Друзья</a>
        </div>
        {% if users %}
            {% for u in users %}
                <div class="user-row">
                    <a href="/user/{{ u.id }}" class="avatar-sm">
                        {% if u.avatar %}<img src="{{ u.avatar_url }}" alt="">
                        {% else %}{{ u.username[0] }}{% endif %}
                    </a>
                    <div class="info">
                        <div class="name">
                            <a href="/user/{{ u.id }}">{{ u.username }}</a>
                            {% if u.id == me.id %}
                                <span class="badge me-badge">это вы</span>
                            {% elif me.is_friend(u) %}
                                <span class="badge friend-badge">друг</span>
                            {% elif me.is_following(u) %}
                                <span class="badge following-badge">вы подписаны</span>
                            {% endif %}
                        </div>
                        <div class="bio">{{ u.bio or 'Нет описания' }}</div>
                    </div>
                    {% if u.id != me.id %}
                        <a href="/messages/{{ u.id }}" class="btn btn-primary btn-sm">💬</a>
                    {% endif %}
                </div>
            {% endfor %}
        {% else %}<div class="empty">Пусто 🤷</div>{% endif %}
    </div>
</body>
</html>
"""


PROFILE_EDIT_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    """ + CSRF_META + """
    <title>Редактирование профиля</title>
    """ + BASE_STYLE + CSRF_JS + """
</head>
<body>
    <div class="container" style="max-width: 520px;">
        <div class="card">
            <h2 class="center">Редактировать профиль</h2>
            <div class="center" style="margin-bottom: 20px;">
                <div class="avatar-lg" style="margin: 0 auto 15px;">
                    {% if user.avatar %}<img src="{{ user.avatar_url }}" alt="">
                    {% else %}{{ user.username[0] }}{% endif %}
                </div>
                <form id="avatarForm">
                    <input type="file" id="avatarInput" name="avatar"
                           accept="image/*" style="display:none;">
                    <button type="button" class="btn btn-secondary btn-sm"
                            onclick="document.getElementById('avatarInput').click()">
                        Выбрать аватарку
                    </button>
                    <button type="submit" class="btn btn-success btn-sm"
                            id="uploadBtn" disabled>Загрузить</button>
                </form>
                <p id="avatarMsg" class="msg"></p>
            </div>
            <hr style="border:0; border-top:1px solid #eee; margin: 15px 0;">
            <form id="editForm">
                <label for="username">Логин</label>
                <input type="text" id="username" value="{{ user.username }}" required>
                <label for="bio">О себе</label>
                <textarea id="bio" placeholder="Расскажите о себе...">{{ user.bio or '' }}</textarea>
                <label for="password">Новый пароль</label>
                <input type="password" id="password" placeholder="Оставьте пустым, чтобы не менять">
                <div class="hint">Минимум 8 символов, заглавная буква, цифра</div>
                <button type="submit" class="btn btn-primary btn-block">Сохранить</button>
            </form>
            <a href="/profile" class="btn btn-secondary btn-block">← В профиль</a>
        </div>
    </div>
    <script>
        document.getElementById('editForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('username').value.trim();
            const bio = document.getElementById('bio').value.trim();
            const password = document.getElementById('password').value;
            const r = await fetch('/api/profile/update', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ username, bio, password })
            });
            const data = await r.json();
            alert(data.message);
            if (data.ok) window.location.href = '/profile';
        });
        const avatarForm = document.getElementById('avatarForm');
        const avatarInput = document.getElementById('avatarInput');
        const uploadBtn = document.getElementById('uploadBtn');
        const avatarMsg = document.getElementById('avatarMsg');
        avatarInput.addEventListener('change', () => {
            uploadBtn.disabled = !avatarInput.files.length;
            avatarMsg.textContent = '';
        });
        avatarForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (!avatarInput.files.length) return;
            const fd = new FormData();
            fd.append('avatar', avatarInput.files[0]);
            avatarMsg.textContent = 'Загрузка...';
            const r = await fetch('/api/profile/avatar', { method: 'POST', body: fd });
            const data = await r.json();
            avatarMsg.textContent = data.message;
            avatarMsg.className = 'msg ' + (data.ok ? 'success' : 'error');
            if (data.ok) setTimeout(() => window.location.reload(), 700);
        });
    </script>
</body>
</html>
"""


MESSAGES_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    """ + CSRF_META + """
    <title>Сообщения</title>
    """ + BASE_STYLE + CSRF_JS + """
    <style>
        .chat-wrap { display: flex; gap: 15px; height: 70vh; min-height: 500px; }
        .dialogs { width: 260px; background: #fff; border-radius: 12px;
                   box-shadow: 0 2px 10px rgba(0,0,0,0.05); overflow-y: auto;
                   flex-shrink: 0; }
        .dialog { display: flex; align-items: center; gap: 10px; padding: 12px 14px;
                  text-decoration: none; color: inherit;
                  border-bottom: 1px solid #f0f0f0; transition: background 0.15s; }
        .dialog:hover { background: #f8f9fa; }
        .dialog.active { background: #e7f1ff; }
        .dialog .info { flex: 1; min-width: 0; }
        .dialog .name { font-weight: bold; font-size: 14px; color: #222;
                        overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .dialog .preview { font-size: 12px; color: #888; margin-top: 3px;
                           overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .chat { flex: 1; background: #fff; border-radius: 12px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.05); display: flex;
                flex-direction: column; min-width: 0; }
        .chat-header { padding: 14px 18px; border-bottom: 1px solid #eee;
                       display: flex; align-items: center; gap: 10px; }
        .chat-header .name { font-weight: bold; font-size: 16px; }
        .chat-header a { color: #222; text-decoration: none; }
        .chat-header a:hover { text-decoration: underline; }
        .messages { flex: 1; overflow-y: auto; padding: 18px; background: #f8f9fa; }
        .msg-row { display: flex; gap: 8px; margin-bottom: 10px; }
        .msg-row.me { flex-direction: row-reverse; }
        .msg-bubble { max-width: 70%; padding: 9px 14px; border-radius: 16px;
                      background: #fff; font-size: 14px; color: #222;
                      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
                      word-wrap: break-word; white-space: pre-wrap; }
        .msg-row.me .msg-bubble { background: #007bff; color: #fff; }
        .msg-time { font-size: 10px; color: #888; align-self: flex-end;
                    margin-bottom: 4px; flex-shrink: 0; }
        .chat-input { display: flex; gap: 8px; padding: 12px 14px;
                      border-top: 1px solid #eee; }
        .chat-input input { margin: 0; flex: 1; }
        .empty-chat { display: flex; align-items: center; justify-content: center;
                      flex: 1; color: #999; font-size: 15px; text-align: center;
                      padding: 30px; }
    </style>
</head>
<body>
    <div class="container" style="max-width: 900px;">
        <div class="topbar">
            <h2>💬 Сообщения</h2>
            <div>
                <a href="/wall">Стена</a>
                <a href="/users">Люди</a>
                <a href="/profile">Профиль</a>
            </div>
        </div>
        <div class="chat-wrap">
            <div class="dialogs">
                {% if dialogs %}
                    {% for d in dialogs %}
                        <a href="/messages/{{ d.user.id }}"
                           class="dialog {% if other and other.id == d.user.id %}active{% endif %}">
                            <div class="avatar-sm" style="width:38px;height:38px;font-size:16px;">
                                {% if d.user.avatar %}<img src="{{ d.user.avatar_url }}" alt="">
                                {% else %}{{ d.user.username[0] }}{% endif %}
                            </div>
                            <div class="info">
                                <div class="name">{{ d.user.username }}</div>
                                <div class="preview">
                                    {% if d.last.sender_id == me.id %}Вы: {% endif %}
                                    {{ d.last.text[:30] }}{% if d.last.text|length > 30 %}…{% endif %}
                                </div>
                            </div>
                            {% if d.unread %}<span class="unread">{{ d.unread }}</span>{% endif %}
                        </a>
                    {% endfor %}
                {% else %}
                    <div style="padding: 20px; color: #888; text-align: center; font-size: 14px;">
                        Пока нет диалогов.<br>
                        <a href="/users" style="color:#007bff;">Найти людей →</a>
                    </div>
                {% endif %}
            </div>
            <div class="chat">
                {% if other %}
                    <div class="chat-header">
                        <a href="/user/{{ other.id }}" class="avatar-sm"
                           style="width:38px;height:38px;font-size:16px;">
                            {% if other.avatar %}<img src="{{ other.avatar_url }}" alt="">
                            {% else %}{{ other.username[0] }}{% endif %}
                        </a>
                        <a class="name" href="/user/{{ other.id }}">{{ other.username }}</a>
                    </div>
                    <div class="messages" id="messages">
                        {% for m in conversation %}
                            <div class="msg-row {% if m.sender_id == me.id %}me{% endif %}"
                                 data-id="{{ m.id }}">
                                <div class="msg-bubble">{{ m.text }}</div>
                                <div class="msg-time">{{ m.created_at.strftime('%H:%M') }}</div>
                            </div>
                        {% endfor %}
                    </div>
                    <form class="chat-input" id="msgForm" data-other="{{ other.id }}">
                        <input type="text" id="msgText" maxlength="1000"
                               placeholder="Написать сообщение..." autofocus>
                        <button type="submit" class="btn btn-primary">Отправить</button>
                    </form>
                {% else %}
                    <div class="empty-chat">
                        Выберите диалог слева или
                        <a href="/users" style="color:#007bff; margin-left:4px;">
                            найдите человека
                        </a>
                    </div>
                {% endif %}
            </div>
        </div>
    </div>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.min.js"></script>
    <script>
        const socket = io();
        const messages = document.getElementById('messages');
        if (messages) messages.scrollTop = messages.scrollHeight;
        const form = document.getElementById('msgForm');
        if (form) {
            const textEl = document.getElementById('msgText');
            const otherId = parseInt(form.dataset.other);
            socket.emit('join', { with_user: otherId });
            form.addEventListener('submit', (e) => {
                e.preventDefault();
                const text = textEl.value.trim();
                if (!text) return;
                socket.emit('send_message', { to_user: otherId, text: text });
                textEl.value = '';
            });
            socket.on('new_message', (data) => {
                if (data.from_user === otherId || data.to_user === otherId) {
                    messages.insertAdjacentHTML('beforeend', data.html);
                    messages.scrollTop = messages.scrollHeight;
                }
            });
        }
    </script>
</body>
</html>
"""


# ============================================================
# КОНТЕКСТ-ПРОЦЕССОР
# ============================================================

@app.context_processor
def inject_unread():
    me = current_user()
    if not me:
        return {'unread_total': 0}
    cnt = Message.query.filter_by(recipient_id=me.id, is_read=False).count()
    return {'unread_total': cnt}


# ============================================================
# МАРШРУТЫ
# ============================================================

@app.route('/')
def index():
    if current_user():
        return redirect(url_for('wall'))
    return redirect(url_for('login_page'))


@app.route('/register-page')
def register_page():
    return render_template('register.html')


@app.route('/login-page')
def login_page():
    return render_template('login.html')


@app.route('/profile')
def profile():
    user = current_user()
    if not user:
        return redirect(url_for('login_page'))
    return render_template('profile.html', user=user)


@app.route('/profile/edit')
def profile_edit():
    user = current_user()
    if not user:
        return redirect(url_for('login_page'))
    return render_template_string(PROFILE_EDIT_TEMPLATE, user=user)


@app.route('/users')
def users_list():
    me = current_user()
    if not me:
        return redirect(url_for('login_page'))
    tab = request.args.get('tab', 'all')
    if tab == 'following':
        users = me.following.all()
    elif tab == 'followers':
        users = me.followers_rel.all()
    elif tab == 'friends':
        users = [u for u in me.following.all() if me.is_friend(u)]
    else:
        users = User.query.order_by(User.id).all()
    return render_template_string(USERS_TEMPLATE, users=users, me=me, tab=tab)


@app.route('/user/<int:user_id>')
def user_view(user_id):
    me = current_user()
    if not me:
        return redirect(url_for('login_page'))
    user = User.query.get(user_id)
    if user is None:
        abort(404)
    return render_template_string(
        USER_VIEW_TEMPLATE,
        user=user,
        posts=Post.query.filter_by(user_id=user.id)
                        .order_by(Post.created_at.desc()).all(),
        is_me=(user.id == me.id),
        i_follow=me.is_following(user) if user.id != me.id else False,
        follows_me=user.is_following(me) if user.id != me.id else False,
        is_friend=me.is_friend(user) if user.id != me.id else False,
        followers_count=user.followers_rel.count(),
        following_count=user.following.count()
    )


@app.route('/wall')
def wall():
    me = current_user()
    if not me:
        return redirect(url_for('login_page'))
    scope = request.args.get('scope', 'all')
    q = Post.query
    if scope == 'following':
        following_ids = [u.id for u in me.following.all()]
        q = q.filter(or_(Post.user_id.in_(following_ids), Post.user_id == me.id))
    posts = q.order_by(Post.created_at.desc()).limit(100).all()
    return render_template_string(WALL_TEMPLATE, me=me, posts=posts)


@app.route('/search')
def search():
    me = current_user()
    if not me:
        return redirect(url_for('login_page'))
    q = (request.args.get('q') or '').strip()
    posts = []
    if q and len(q) <= 100:
        posts = (Post.query.filter(Post.text.ilike(f'%{q}%'))
                 .order_by(Post.created_at.desc()).limit(100).all())
    return render_template_string(SEARCH_TEMPLATE, me=me, posts=posts, q=q)


@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    filename = secure_filename(filename)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/messages')
@app.route('/messages/<int:user_id>')
def messages_page(user_id=None):
    me = current_user()
    if not me:
        return redirect(url_for('login_page'))
    other = None
    conversation = []
    if user_id:
        other = User.query.get(user_id)
        if other is None or other.id == me.id:
            return redirect(url_for('messages_page'))
        Message.query.filter_by(sender_id=other.id, recipient_id=me.id,
                                is_read=False).update({'is_read': True})
        db.session.commit()
        conversation = get_conversation(me, other)
    dialogs = get_dialogs(me)
    return render_template_string(
        MESSAGES_TEMPLATE, me=me, dialogs=dialogs,
        other=other, conversation=conversation
    )


# ============================================================
# API
# ============================================================

@app.route('/api/register', methods=['POST'])
@limiter.limit("10 per hour")
def api_register():
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''

    ok, msg = validate_username(username)
    if not ok:
        return jsonify({'ok': False, 'message': msg}), 400
    ok, msg = validate_password(password)
    if not ok:
        return jsonify({'ok': False, 'message': msg}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'ok': False, 'message': 'Такой пользователь уже существует!'}), 409

    user = User(username=username)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({'ok': True, 'message': 'Регистрация успешна!'})


@app.route('/api/login', methods=['POST'])
@limiter.limit("10 per minute")
def api_login():
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    user = User.query.filter_by(username=username).first()
    if user is None:
        return jsonify({'ok': False, 'message': 'Такого пользователя не существует'}), 404
    if not user.check_password(password):
        return jsonify({'ok': False, 'message': 'Неверный пароль'}), 401
    session.clear()
    session['user_id'] = user.id
    session['username'] = user.username
    session.permanent = True
    return jsonify({'ok': True, 'message': 'Вы успешно зашли!',
                    'redirect': url_for('wall')})


@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'ok': True})


@app.route('/api/profile/update', methods=['POST'])
def api_profile_update():
    user = current_user()
    if not user:
        return jsonify({'ok': False, 'message': 'Не авторизован'}), 401
    data = request.get_json() or {}
    new_username = (data.get('username') or '').strip()
    new_bio = (data.get('bio') or '').strip()
    new_password = data.get('password') or ''

    ok, msg = validate_username(new_username)
    if not ok:
        return jsonify({'ok': False, 'message': msg}), 400
    if len(new_bio) > 500:
        return jsonify({'ok': False, 'message': 'Био слишком длинное'}), 400

    existing = User.query.filter_by(username=new_username).first()
    if existing and existing.id != user.id:
        return jsonify({'ok': False, 'message': 'Такой логин уже занят'}), 409

    user.username = new_username
    user.bio = new_bio
    if new_password:
        ok, msg = validate_password(new_password)
        if not ok:
            return jsonify({'ok': False, 'message': msg}), 400
        user.set_password(new_password)
    db.session.commit()
    session['username'] = user.username
    return jsonify({'ok': True, 'message': 'Профиль обновлён!'})


@app.route('/api/profile/avatar', methods=['POST'])
def api_profile_avatar():
    user = current_user()
    if not user:
        return jsonify({'ok': False, 'message': 'Не авторизован'}), 401
    if 'avatar' not in request.files:
        return jsonify({'ok': False, 'message': 'Файл не выбран'}), 400
    try:
        filename = save_image(request.files['avatar'])
    except ValueError as e:
        return jsonify({'ok': False, 'message': str(e)}), 400
    if user.avatar:
        old = os.path.join(app.config['UPLOAD_FOLDER'], user.avatar)
        if os.path.exists(old):
            try: os.remove(old)
            except OSError: pass
    user.avatar = filename
    db.session.commit()
    return jsonify({'ok': True, 'message': 'Аватарка обновлена!',
                    'avatar_url': url_for('uploaded_file', filename=filename)})


@app.route('/api/posts', methods=['POST'])
def api_posts_create():
    user = current_user()
    if not user:
        return jsonify({'ok': False, 'message': 'Не авторизован'}), 401

    if request.content_type and 'multipart/form-data' in request.content_type:
        text = (request.form.get('text') or '').strip()
        image = request.files.get('image')
    else:
        data = request.get_json() or {}
        text = (data.get('text') or '').strip()
        image = None

    if not text:
        return jsonify({'ok': False, 'message': 'Пустой пост'}), 400
    if len(text) > 1000:
        return jsonify({'ok': False, 'message': 'Максимум 1000 символов'}), 400

    post = Post(text=text, user_id=user.id)
    if image and image.filename:
        try:
            post.image = save_image(image)
        except ValueError as e:
            return jsonify({'ok': False, 'message': str(e)}), 400

    db.session.add(post)
    db.session.commit()
    html = render_template('__post.html', post=post, me=user)
    return jsonify({'ok': True, 'html': html})


@app.route('/api/posts/<int:post_id>', methods=['PUT'])
def api_post_update(post_id):
    me = current_user()
    if not me:
        return jsonify({'ok': False, 'message': 'Не авторизован'}), 401
    post = Post.query.get_or_404(post_id)
    if post.user_id != me.id:
        return jsonify({'ok': False, 'message': 'Нет прав'}), 403
    data = request.get_json() or {}
    text = (data.get('text') or '').strip()
    if not text or len(text) > 1000:
        return jsonify({'ok': False, 'message': 'Некорректный текст'}), 400
    post.text = text
    db.session.commit()
    return jsonify({'ok': True})


@app.route('/api/posts/<int:post_id>', methods=['DELETE'])
def api_post_delete(post_id):
    me = current_user()
    if not me:
        return jsonify({'ok': False, 'message': 'Не авторизован'}), 401
    post = Post.query.get_or_404(post_id)
    if post.user_id != me.id:
        return jsonify({'ok': False, 'message': 'Нет прав'}), 403
    if post.image:
        p = os.path.join(app.config['UPLOAD_FOLDER'], post.image)
        if os.path.exists(p):
            try: os.remove(p)
            except OSError: pass
    db.session.delete(post)
    db.session.commit()
    return jsonify({'ok': True})


@app.route('/api/posts/<int:post_id>/like', methods=['POST'])
def api_post_like(post_id):
    me = current_user()
    if not me:
        return jsonify({'ok': False, 'message': 'Не авторизован'}), 401
    post = Post.query.get_or_404(post_id)
    like = Like.query.filter_by(user_id=me.id, post_id=post.id).first()
    if like:
        db.session.delete(like); liked = False
    else:
        db.session.add(Like(user_id=me.id, post_id=post.id)); liked = True
    db.session.commit()
    return jsonify({'ok': True, 'liked': liked, 'count': post.likes_count()})


@app.route('/api/posts/<int:post_id>/comments', methods=['POST'])
def api_post_comment(post_id):
    me = current_user()
    if not me:
        return jsonify({'ok': False, 'message': 'Не авторизован'}), 401
    post = Post.query.get_or_404(post_id)
    data = request.get_json() or {}
    text = (data.get('text') or '').strip()
    if not text or len(text) > 500:
        return jsonify({'ok': False, 'message': 'Некорректный комментарий'}), 400
    c = Comment(text=text, user_id=me.id, post_id=post.id)
    db.session.add(c)
    db.session.commit()
    html = render_template_string("""
        <div class="comment">
            <a href="/user/{{ c.author.id }}" class="avatar-sm"
               style="width:32px;height:32px;font-size:14px;">
                {% if c.author.avatar %}<img src="{{ c.author.avatar_url }}" alt="">
                {% else %}{{ c.author.username[0] }}{% endif %}
            </a>
            <div class="comment-body">
                <a class="comment-author" href="/user/{{ c.author.id }}">
                    {{ c.author.username }}
                </a>
                <div class="comment-text">{{ c.text }}</div>
            </div>
        </div>
    """, c=c)
    return jsonify({'ok': True, 'html': html, 'total': len(post.comments)})


@app.route('/api/follow/<int:user_id>', methods=['POST'])
def api_follow(user_id):
    me = current_user()
    if not me:
        return jsonify({'ok': False, 'message': 'Не авторизован'}), 401
    if me.id == user_id:
        return jsonify({'ok': False, 'message': 'Нельзя подписаться на себя'}), 400
    other = User.query.get_or_404(user_id)
    if me.is_following(other):
        me.following.remove(other); following = False
    else:
        me.following.append(other); following = True
    db.session.commit()
    return jsonify({'ok': True, 'following': following})


# ============================================================
# WEBSOCKET
# ============================================================

@socketio.on('join')
def on_join(data):
    me = current_user()
    if not me:
        return False
    try:
        with_user = int(data.get('with_user', 0))
    except (TypeError, ValueError):
        return False
    other = User.query.get(with_user)
    if not other or other.id == me.id:
        return False
    room = f"chat_{min(me.id, other.id)}_{max(me.id, other.id)}"
    join_room(room)
    emit('joined', {'room': room})


@socketio.on('send_message')
def on_send_message(data):
    me = current_user()
    if not me:
        return
    try:
        to_user = int(data.get('to_user', 0))
    except (TypeError, ValueError):
        return
    text = (data.get('text') or '').strip()
    if not text or len(text) > 1000 or to_user == me.id:
        return
    other = User.query.get(to_user)
    if not other:
        return
    m = Message(text=text, sender_id=me.id, recipient_id=other.id)
    db.session.add(m)
    db.session.commit()
    room = f"chat_{min(me.id, other.id)}_{max(me.id, other.id)}"
    html = _msg_html(m, me)
    emit('new_message', {
        'from_user': me.id, 'to_user': other.id,
        'html': html, 'id': m.id
    }, room=room)


# ============================================================
# ЗАПУСК
# ============================================================

if __name__ == '__main__':
    socketio.run(
        app,
        host=os.getenv('HOST', '127.0.0.1'),
        port=int(os.getenv('PORT', '5000')),
        debug=os.getenv('DEBUG', 'True') == 'True',
        allow_unsafe_werkzeug=True
    )