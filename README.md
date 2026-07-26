# Python Wiki (Flask)

A lightweight wiki built with Flask.

Pages are written in Markdown, stored as `.md` files on the server, rendered to HTML, and organized with a persistent left sidebar.

## Features

- Authentication at `/login` (by default, user is `admin` and password is `admin`)
- Session-like auth using auth codes stored in cookies and persisted in SQLite
- Argon2 password verification
- Markdown page creation, editing, and deletion for authenticated users only
- Configurable welcome page and configurable left sidebar (both in Markdown)
- Persistent left panel on all views
- Page search by title or content
- Image library at `/media` with file upload and reusable `/uploads/...` URLs
- Light and dark theme toggle saved in cookies

## Important Authentication Note

This project does **not** support user sign-up from the UI.

Users must be inserted manually into the SQLite database.

To generate a password hash, use the helper script:

- `argonHasher.py`

It prompts for a plaintext password and prints an Argon2 hash.

## Project Structure

- `app.py`: main Flask application
- `main.py`: app entry point
- `argonHasher.py`: Argon2 password hash helper
- `requirements.txt`: Python dependencies
- `templates/`: HTML templates
- `static/`: CSS styles
- `data/pages/`: Markdown page files
- `data/uploads/`: uploaded image files
- `data/wiki.sqlite3`: SQLite database

## Requirements

- Python 3.10+
- pip

## Installation

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Run

```bash
python main.py
```

Server starts at:

- http://127.0.0.1:5000

## Manual User Creation

### 1. Generate Argon2 password hash

```bash
python argonHasher.py
```

Copy the generated hash.

### 2. Insert the user into SQLite

Open SQLite for `data/wiki.sqlite3` and run:

```sql
INSERT INTO users (username, password_hash, active)
VALUES ('admin', '<PASTE_ARGON2_HASH_HERE>', 1);
```

After that, log in at `/login` with the username and original plaintext password.

## Basic Usage

1. Open the home page `/`.
2. Log in at `/login`.
3. Create pages from `/new`.
4. Edit pages using the pencil button.
5. Search pages at `/search`.
6. Upload images at `/media` and embed them in Markdown pages.

Example image embed in Markdown editor:

```html
<img src="/uploads/your-image.jpg" width="160">
```

## Notes

- Only authenticated users can create, edit, or delete wiki content.
- Welcome and sidebar content are editable Markdown pages.
- Auth codes are stored in SQLite and sent to the browser as cookies.
- This setup uses Flask development server; use a production WSGI server for deployment.
