import sqlite3
import time
from pathlib import Path

from fastapi import FastAPI, Request, Form
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from starlette.middleware.sessions import SessionMiddleware
from passlib.context import CryptContext

APP_SECRET = "change-me-to-random-long-string"  # обязательно поменяй

DB_PATH = Path("auth.db")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

MAX_FAILS = 5
LOCK_SECONDS = 60

app = FastAPI()

# "Сессии" через подписанную cookie
app.add_middleware(SessionMiddleware, secret_key=APP_SECRET, same_site="lax")

# static + templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            fails INTEGER NOT NULL DEFAULT 0,
            locked_until INTEGER NOT NULL DEFAULT 0
        );
        """
    )
    conn.commit()
    conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


def current_user(request: Request):
    return request.session.get("user")


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "user": current_user(request)},
    )


@app.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    return templates.TemplateResponse("register.html", {"request": request, "user": current_user(request)})


@app.post("/register")
def register(request: Request, username: str = Form(...), password: str = Form(...)):
    username = username.strip()

    if len(username) < 3 or len(password) < 8:
        request.session["flash"] = "Логин минимум 3 символа, пароль минимум 8."
        return RedirectResponse("/register", status_code=303)

    pw_hash = pwd_context.hash(password)

    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, pw_hash),
        )
        conn.commit()
        conn.close()
    except sqlite3.IntegrityError:
        request.session["flash"] = "Такой логин уже существует."
        return RedirectResponse("/register", status_code=303)

    request.session["flash"] = "Пользователь создан. Теперь войди."
    return RedirectResponse("/login", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "user": current_user(request)})


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    username = username.strip()

    conn = get_db()
    row = conn.execute(
        "SELECT id, username, password_hash, fails, locked_until FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    # Не палим, существует ли пользователь
    if not row:
        time.sleep(0.3)
        request.session["flash"] = "Неверный логин или пароль."
        return RedirectResponse("/login", status_code=303)

    now = int(time.time())
    if row["locked_until"] > now:
        request.session["flash"] = "Аккаунт временно заблокирован. Попробуй позже."
        return RedirectResponse("/login", status_code=303)

    if pwd_context.verify(password, row["password_hash"]):
        conn.execute("UPDATE users SET fails = 0, locked_until = 0 WHERE id = ?", (row["id"],))
        conn.commit()
        conn.close()

        request.session["user"] = row["username"]
        request.session["flash"] = "Вход выполнен."
        return RedirectResponse("/", status_code=303)

    # неверный пароль -> считаем попытки
    fails = row["fails"] + 1
    locked_until = 0
    if fails >= MAX_FAILS:
        locked_until = now + LOCK_SECONDS
        fails = 0

    conn.execute(
        "UPDATE users SET fails = ?, locked_until = ? WHERE id = ?",
        (fails, locked_until, row["id"]),
    )
    conn.commit()
    conn.close()

    request.session["flash"] = "Неверный логин или пароль."
    return RedirectResponse("/login", status_code=303)


@app.get("/logout")
def logout(request: Request):
    request.session.pop("user", None)
    request.session["flash"] = "Выход выполнен."
    return RedirectResponse("/", status_code=303)