import os

SECRET_KEY = os.environ["SECRET_KEY"]
DATABASE_URL = os.environ.get("DATABASE_URL", "postgres://localhost/notes")
