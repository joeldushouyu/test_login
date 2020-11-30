import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
# Create a SQL connection to our SQLite database
con = sqlite3.connect("database.db")

cur = con.cursor()


cursor = cur.execute("SELECT id, username, email, password, safe0 from user")
for row in cursor:
    print("here")
    print("id= {}".format(row[0]))
    print("usernae= {}".format(row[1]))
    print("email= {}".format(row[2]))
    print("safe0 ={}".format(row[3]))



"""
# Return all results of query
cur.execute('SELECT plot_id FROM plots WHERE plot_type="Control"')
cur.fetchall()"""
"""
# Return first result of query
cur.execute('SELECT species FROM species WHERE taxa="Bird"')
cur.fetchone()
"""
# Be sure to close the connection
con.close()