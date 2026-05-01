from database.database import connect
from datetime import datetime, timedelta

def add_user(user_id: str, hashed_digest: str, salt: str, username: str, teams: str = None):
    conn = connect()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (user_id, hashed_digest, salt, username, teams) VALUES (?, ?, ?, ?, ?)",
                       (user_id, hashed_digest, salt, username, teams))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error adding user: {e}")
        return False
    finally:
        conn.close()

def get_user_by_id(user_id: str):
    conn = connect()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT user_id, username, teams FROM users WHERE user_id = ?", (user_id,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    except Exception as e:
        print(f"Error fetching user: {e}")
        return None
    finally:
        conn.close()

def get_user_by_username(username: str):
    conn = connect()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT user_id, username, teams FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    except Exception as e:
        print(f"Error fetching user: {e}")
        return None
    finally:
        conn.close()

def get_user_salt(username: str):
    conn = connect()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT salt FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row:
            return row["salt"]
        return None
    except Exception as e:
        print(f"Error fetching user salt: {e}")
        return None
    finally:
        conn.close()

def is_valid_user(username: str, hashed_digest: str):
    conn = connect()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT hashed_digest FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row and row["hashed_digest"] == hashed_digest:
            return True
        return False
    except Exception as e:
        print(f"Error validating user: {e}")
        return False
    finally:
        conn.close()

def update_user_teams(user_id: str, teams: str):
    conn = connect()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE users SET teams = ? WHERE user_id = ?", (teams, user_id))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error updating user teams: {e}")
        return False
    finally:
        conn.close()

def delete_user(user_id: str):
    conn = connect()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error deleting user: {e}")
        return False
    finally:
        conn.close()




"""

============================ Keys Management ============================

"""




def add_key(key_id: str, key_value: str,user_id: str = None):
    conn = connect()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO keys (key_id, key_value, user_id, created_at) VALUES (?, ?, ?, ?)", (key_id, key_value, user_id, datetime.now()))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error adding key: {e}")
        return False
    finally:        
        conn.close()


def get_key(key_id: str):
    conn = connect()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT key_value FROM keys WHERE key_id = ?", (key_id,))
        row = cursor.fetchone()
        if row:
            return row["key_value"]
        return None
    except Exception as e:
        print(f"Error fetching key: {e}")
        return None
    finally:
        conn.close()

def delete_key(key_id: str):
    conn = connect()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM keys WHERE key_id = ?", (key_id,))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error deleting key: {e}")
        return False
    finally:
        conn.close()

def delete_old_keys(max_age_seconds: int = 3600):
    conn = connect()
    cursor = conn.cursor()
    try:
        cutoff_time = datetime.now() - timedelta(seconds=max_age_seconds)
        cursor.execute("DELETE FROM keys WHERE created_at < ?", (cutoff_time))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error deleting old keys: {e}")
        return False
    finally:
        conn.close()