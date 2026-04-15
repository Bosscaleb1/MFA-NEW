import sqlite3
conn = sqlite3.connect('mfa_auth.db')
cur = conn.cursor()
cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
print('tables:', cur.fetchall())
cur.execute("PRAGMA table_info('users')")
print('users_info:', cur.fetchall())
conn.close()
