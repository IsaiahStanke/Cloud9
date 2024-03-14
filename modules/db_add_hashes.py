import sqlite3
import os

# Get the absolute path to the database file
db_file = os.path.abspath("db\\mal_hashes.db")

# connecting to the database
con = sqlite3.connect(db_file)

# creating a cursor to execute and fetch SQL 
cur = con.cursor()

cur.execute("DROP TABLE IF EXISTS hashes")
cur.execute("CREATE TABLE hashes (hash_id INTEGER PRIMARY KEY AUTOINCREMENT, hash_value INTEGER, file_name TEXT, file_type TEXT, status TEXT, notes TEXT)")

cur.execute("""
    INSERT INTO hashes VALUES
            (1, 255255255255, "pyp.exe", ".exe", "active", "N/A")
            """)

# Commit the transaction
con.commit()

