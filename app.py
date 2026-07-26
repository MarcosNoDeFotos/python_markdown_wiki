from __future__ import annotations

import hashlib
import os
import re
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

import bleach
import markdown as md
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

try:
    from bleach.css_sanitizer import CSSSanitizer
except ModuleNotFoundError:
    CSSSanitizer = None
from flask import (
    Flask,
    abort,
    g,
    make_response,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)
from werkzeug.utils import secure_filename


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
PAGES_DIR = DATA_DIR / "pages"
UPLOADS_DIR = DATA_DIR / "uploads"
DB_PATH = DATA_DIR / "wiki.sqlite3"
WELCOME_PATH = PAGES_DIR / "welcome.md"
SIDEBAR_PATH = PAGES_DIR / "sidebar.md"

IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,60}$")
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg"}
RESERVED_IDENTIFIERS = {"login", "logout", "search", "media", "new", "uploads", "theme"}

PH = PasswordHasher()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ensure_directories() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    PAGES_DIR.mkdir(parents=True, exist_ok=True)
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


def close_db(_: object) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    ensure_directories()
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                active INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS auth_codes (
                code_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                last_used_at TEXT,
                revoked_at TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS pages (
                identifier TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                filepath TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                kind TEXT NOT NULL DEFAULT 'page'
            );
            """
        )


def default_welcome_markdown() -> str:
    return """# Welcome\n\nThis is the wiki's front page.\n\n- Use the left panel to navigate.\n- If you are authenticated, you can edit any visible page with the pencil button.\n- Pages are saved as Markdown files on the server.\n"""


def default_sidebar_markdown() -> str:
    return """# Navigation\n\nUse this column to organize sections, shortcuts, and internal links.\n\n## Quick Access\n\n- [Welcome](/)\n- [Search](/search)\n- [Library](/media)\n- [New Page](/new)\n"""


def ensure_seed_files() -> None:
    ensure_directories()
    if not WELCOME_PATH.exists():
        WELCOME_PATH.write_text(default_welcome_markdown(), encoding="utf-8")
    if not SIDEBAR_PATH.exists():
        SIDEBAR_PATH.write_text(default_sidebar_markdown(), encoding="utf-8")


def ensure_page_record(
    db: sqlite3.Connection, identifier: str, title: str, filepath: Path, kind: str = "page"
) -> None:
    timestamp = now_iso()
    db.execute(
        """
        INSERT INTO pages (identifier, title, filepath, created_at, updated_at, kind)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(identifier) DO UPDATE SET
            title = excluded.title,
            filepath = excluded.filepath,
            updated_at = excluded.updated_at,
            kind = excluded.kind
        """,
        (identifier, title, str(filepath), timestamp, timestamp, kind),
    )


def ensure_seed_records() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        ensure_page_record(conn, "welcome", "Welcome", WELCOME_PATH, "system")
        ensure_page_record(conn, "sidebar", "Sidebar", SIDEBAR_PATH, "system")
        conn.commit()


def hash_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def normalize_identifier(value: str) -> str:
    candidate = value.strip().lower().replace(" ", "-")
    candidate = re.sub(r"[^a-z0-9_-]", "", candidate)
    candidate = re.sub(r"-+", "-", candidate).strip("-")
    return candidate


def is_valid_identifier(identifier: str) -> bool:
    return bool(IDENTIFIER_RE.fullmatch(identifier)) and identifier not in RESERVED_IDENTIFIERS


def load_pages(include_system: bool = True) -> list[sqlite3.Row]:
    db = get_db()
    if include_system:
        return db.execute(
            "SELECT * FROM pages ORDER BY CASE WHEN identifier IN ('welcome', 'sidebar') THEN 0 ELSE 1 END, title COLLATE NOCASE"
        ).fetchall()
    return db.execute("SELECT * FROM pages WHERE kind = 'page' ORDER BY title COLLATE NOCASE").fetchall()


def get_page_record(identifier: str) -> sqlite3.Row | None:
    return get_db().execute("SELECT * FROM pages WHERE identifier = ?", (identifier,)).fetchone()


def read_page_file(path: str) -> str:
    file_path = Path(path)
    if not file_path.exists():
        return ""
    return file_path.read_text(encoding="utf-8")


def write_page_file(path: str, content: str) -> None:
    # Normalize newlines to avoid CRLF inflation on repeated edit/save cycles in Windows.
    normalized = content.replace("\r\n", "\n").replace("\r", "\n")
    with Path(path).open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(normalized)


def upsert_page(identifier: str, title: str, content: str, kind: str = "page") -> None:
    file_path = PAGES_DIR / f"{identifier}.md"
    write_page_file(file_path, content)
    db = get_db()
    timestamp = now_iso()
    db.execute(
        """
        INSERT INTO pages (identifier, title, filepath, created_at, updated_at, kind)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(identifier) DO UPDATE SET
            title = excluded.title,
            filepath = excluded.filepath,
            updated_at = excluded.updated_at,
            kind = excluded.kind
        """,
        (identifier, title, str(file_path), timestamp, timestamp, kind),
    )
    db.commit()


def render_markdown(content: str) -> str:
    html = md.markdown(
        content or "",
        extensions=["extra", "fenced_code", "tables", "sane_lists"],
        output_format="html5",
    )
    allowed_tags = sorted(
        set(bleach.sanitizer.ALLOWED_TAGS).union(
            {
                "p",
                "pre",
                "span",
                "div",
                "hr",
                "br",
                "img",
                "h1",
                "h2",
                "h3",
                "h4",
                "h5",
                "h6",
                "table",
                "thead",
                "tbody",
                "tr",
                "th",
                "td",
                "code",
                "blockquote",
            }
        )
    )
    img_attrs = ["src", "alt", "title", "width", "height"]
    css_sanitizer = None
    if CSSSanitizer is not None:
        img_attrs.append("style")
        css_sanitizer = CSSSanitizer(
            allowed_css_properties=["width", "height", "max-width", "min-width", "max-height", "min-height"]
        )

    allowed_attrs = {
        "a": ["href", "title", "rel"],
        "img": img_attrs,
        "code": ["class"],
        "pre": ["class"],
        "th": ["colspan", "rowspan"],
        "td": ["colspan", "rowspan"],
        "*": ["class", "id"],
    }
    if css_sanitizer is not None:
        cleaned = bleach.clean(
            html,
            tags=allowed_tags,
            attributes=allowed_attrs,
            strip=True,
            css_sanitizer=css_sanitizer,
        )
    else:
        cleaned = bleach.clean(
            html,
            tags=allowed_tags,
            attributes=allowed_attrs,
            strip=True,
        )
    return bleach.linkify(cleaned)


def build_sidebar_html() -> tuple[str, list[sqlite3.Row]]:
    sidebar_markdown = read_page_file(str(SIDEBAR_PATH))
    sidebar_html = render_markdown(sidebar_markdown)
    pages = load_pages(include_system=False)
    return sidebar_html, pages


def is_authenticated() -> bool:
    return g.get("user") is not None


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not is_authenticated():
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


@app.before_request
def load_user_and_theme() -> None:
    g.user = None
    g.theme = request.cookies.get("theme", "light")
    g.sidebar_html, g.sidebar_pages = build_sidebar_html()

    code = request.cookies.get("auth_code")
    if not code:
        return

    code_hash = hash_code(code)
    row = get_db().execute(
        """
        SELECT u.id, u.username
        FROM auth_codes a
        JOIN users u ON u.id = a.user_id
        WHERE a.code_hash = ? AND a.revoked_at IS NULL AND u.active = 1
        """,
        (code_hash,),
    ).fetchone()
    if row:
        g.user = row
        get_db().execute("UPDATE auth_codes SET last_used_at = ? WHERE code_hash = ?", (now_iso(), code_hash))
        get_db().commit()


@app.teardown_appcontext
def teardown_db(exception: object) -> None:
    close_db(exception)


@app.context_processor
def inject_globals() -> dict[str, object]:
    return {
        "current_user": g.get("user"),
        "theme": g.get("theme", "light"),
        "sidebar_html": g.get("sidebar_html", ""),
        "sidebar_pages": g.get("sidebar_pages", []),
    }


def page_context(page_row: sqlite3.Row, content: str) -> dict[str, object]:
    if page_row["kind"] == "system":
        edit_url = url_for("edit_system_page", identifier=page_row["identifier"])
        delete_url = None
    else:
        edit_url = url_for("edit_page", identifier=page_row["identifier"])
        delete_url = url_for("delete_page", identifier=page_row["identifier"])
    return {
        "page": page_row,
        "page_html": render_markdown(content),
        "edit_url": edit_url if is_authenticated() else None,
        "delete_url": delete_url if is_authenticated() else None,
    }


@app.route("/")
def home():
    page = get_page_record("welcome")
    if page is None:
        upsert_page("welcome", "Welcome", default_welcome_markdown(), kind="system")
        page = get_page_record("welcome")
    content = read_page_file(page["filepath"])
    return render_template("page.html", **page_context(page, content))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    next_url = request.args.get("next") or request.form.get("next") or url_for("home")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT id, username, password_hash FROM users WHERE username = ? AND active = 1",
            (username,),
        ).fetchone()

        if user is None:
            error = "Invalid username or password."
        else:
            try:
                PH.verify(user["password_hash"], password)
            except VerifyMismatchError:
                error = "Invalid username or password."
            else:
                auth_code = secrets.token_urlsafe(48)
                code_hash = hash_code(auth_code)
                get_db().execute(
                    """
                    INSERT INTO auth_codes (code_hash, user_id, created_at, last_used_at, revoked_at)
                    VALUES (?, ?, ?, ?, NULL)
                    """,
                    (code_hash, user["id"], now_iso(), now_iso()),
                )
                get_db().commit()
                response = make_response(redirect(next_url))
                response.set_cookie(
                    "auth_code",
                    auth_code,
                    httponly=True,
                    samesite="Lax",
                    max_age=60 * 60 * 24 * 30,
                    path="/",
                )
                return response

    return render_template("login.html", error=error, next_url=next_url)


@app.route("/logout", methods=["POST"])
def logout():
    code = request.cookies.get("auth_code")
    response = make_response(redirect(url_for("home")))
    response.delete_cookie("auth_code", path="/")
    if code:
        get_db().execute("UPDATE auth_codes SET revoked_at = ? WHERE code_hash = ?", (now_iso(), hash_code(code)))
        get_db().commit()
    return response


@app.route("/search")
def search():
    query = request.args.get("q", "").strip()
    results: list[dict[str, str]] = []
    if query:
        lowered = query.lower()
        for page in load_pages(include_system=False):
            content = read_page_file(page["filepath"])
            if lowered in page["title"].lower() or lowered in content.lower():
                results.append(
                    {
                        "identifier": page["identifier"],
                        "title": page["title"],
                        "snippet": content[:240].strip().replace("\n", " "),
                    }
                )
    return render_template("search.html", query=query, results=results)


@app.route("/media", methods=["GET", "POST"])
def media():
    message = None
    error = None

    if request.method == "POST":
        if not is_authenticated():
            abort(403)
        uploaded = request.files.get("image")
        if uploaded is None or not uploaded.filename:
            error = "Select a valid image."
        else:
            original_name = secure_filename(uploaded.filename)
            suffix = Path(original_name).suffix.lower()
            if suffix not in IMAGE_EXTENSIONS:
                error = "Format not allowed. Use png, jpg, jpeg, gif, webp, or svg."
            else:
                filename = f"{secrets.token_hex(12)}{suffix}"
                uploaded.save(UPLOADS_DIR / filename)
                message = filename

    files = sorted(
        [path.name for path in UPLOADS_DIR.iterdir() if path.is_file() and path.suffix.lower() in IMAGE_EXTENSIONS],
        reverse=True,
    )
    return render_template("media.html", files=files, message=message, error=error)


@app.route("/uploads/<path:filename>")
def uploads(filename: str):
    return send_from_directory(UPLOADS_DIR, filename)


@app.route("/new", methods=["GET", "POST"])
@login_required
def create_page():
    error = None
    initial_identifier = ""
    initial_title = ""
    initial_content = ""

    if request.method == "POST":
        identifier = normalize_identifier(request.form.get("identifier", ""))
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "")

        initial_identifier = identifier
        initial_title = title
        initial_content = content

        if not identifier:
            error = "Identifier is required."
        elif not is_valid_identifier(identifier):
            error = "The identifier can only contain lowercase letters, numbers, hyphens, and underscores."
        elif get_page_record(identifier) is not None:
            error = "A page with that identifier already exists."
        elif not title:
            error = "Title is required."
        else:
            upsert_page(identifier, title, content)
            return redirect(url_for("view_page", identifier=identifier))

    return render_template(
        "edit.html",
        form_mode="create",
        page=None,
        error=error,
        page_identifier=initial_identifier,
        page_title=initial_title,
        page_content=initial_content,
        submit_label="Crear página",
    )


@app.route("/system/<string:identifier>/edit", methods=["GET", "POST"])
@login_required
def edit_system_page(identifier: str):
    if identifier not in {"welcome", "sidebar"}:
        abort(404)
    page = get_page_record(identifier)
    if page is None:
        abort(404)

    error = None
    current_content = read_page_file(page["filepath"])
    current_title = page["title"]

    if request.method == "POST":
        current_title = request.form.get("title", "").strip()
        current_content = request.form.get("content", "")
        if not current_title:
            error = "Title is required."
        else:
            upsert_page(identifier, current_title, current_content, kind="system")
            return redirect(url_for("home") if identifier == "welcome" else url_for("view_page", identifier="welcome"))

    return render_template(
        "edit.html",
        form_mode="edit",
        page=page,
        error=error,
        page_identifier=identifier,
        page_title=current_title,
        page_content=current_content,
        submit_label="Guardar cambios",
    )


@app.route("/<string:identifier>")
def view_page(identifier: str):
    if identifier in {"login", "logout", "search", "media", "new", "uploads", "theme", "system"}:
        abort(404)
    page = get_page_record(identifier)
    if page is None:
        abort(404)
    content = read_page_file(page["filepath"])
    return render_template("page.html", **page_context(page, content))


@app.route("/<string:identifier>/edit", methods=["GET", "POST"])
@login_required
def edit_page(identifier: str):
    page = get_page_record(identifier)
    if page is None:
        abort(404)
    if page["kind"] == "system":
        return redirect(url_for("edit_system_page", identifier=identifier))

    error = None
    current_content = read_page_file(page["filepath"])
    current_title = page["title"]

    if request.method == "POST":
        current_title = request.form.get("title", "").strip()
        current_content = request.form.get("content", "")
        if not current_title:
            error = "Title is required."
        else:
            upsert_page(identifier, current_title, current_content, kind="page")
            return redirect(url_for("view_page", identifier=identifier))

    return render_template(
        "edit.html",
        form_mode="edit",
        page=page,
        error=error,
        page_identifier=identifier,
        page_title=current_title,
        page_content=current_content,
        submit_label="Guardar cambios",
    )


@app.route("/<string:identifier>/delete", methods=["POST"])
@login_required
def delete_page(identifier: str):
    page = get_page_record(identifier)
    if page is None or page["kind"] != "page":
        abort(404)
    file_path = Path(page["filepath"])
    if file_path.exists():
        file_path.unlink()
    get_db().execute("DELETE FROM pages WHERE identifier = ?", (identifier,))
    get_db().commit()
    return redirect(url_for("home"))


@app.route("/theme", methods=["POST"])
def set_theme():
    theme = request.form.get("theme", "light")
    if theme not in {"light", "dark"}:
        theme = "light"
    response = make_response(redirect(request.referrer or url_for("home")))
    response.set_cookie("theme", theme, max_age=60 * 60 * 24 * 365, samesite="Lax", path="/")
    return response


init_db()
ensure_seed_files()
ensure_seed_records()


if __name__ == "__main__":
    app.run(debug=True)