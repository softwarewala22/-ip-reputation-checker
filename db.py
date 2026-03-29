<<<<<<< HEAD
import sqlite3

DB_NAME = "ip_cache.db"

def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
=======
import sqlite3

DB_NAME = "ip_cache.db"

def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
>>>>>>> 88376c2dc64b4668dff9880171e5ff3d85432dd0
    return conn