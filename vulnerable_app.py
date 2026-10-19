import sqlite3


def get_user_by_name(db_path: str, username: str) -> list:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return results


def get_user_by_name_safe(db_path: str, username: str) -> list:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    results = cursor.fetchall()
    conn.close()
    return results
