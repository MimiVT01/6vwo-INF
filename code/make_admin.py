import sqlite3

# Replace this with the B-Number of the user you want to make admin
bnumber = "B211264"

# Connect to the database
conn = sqlite3.connect("shop.db")
cur = conn.cursor()

# Update the user to admin
cur.execute("UPDATE users SET is_admin = 1 WHERE bnumber = ?", (bnumber,))
conn.commit()
conn.close()

print(f"{bnumber} is now an admin!")
