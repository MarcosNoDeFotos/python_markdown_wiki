from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = BASE_DIR / "data"
PAGES_DIR = DATA_DIR / "pages"
UPLOADS_DIR = DATA_DIR / "uploads"
DB_PATH = DATA_DIR / "wiki.sqlite3"
WELCOME_PATH = PAGES_DIR / "welcome.md"
SIDEBAR_PATH = PAGES_DIR / "sidebar.md"