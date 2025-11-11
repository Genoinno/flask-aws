def query(db, query: str, fields: tuple, fetch = False):
    with db.cursor(dictionary=True) as cursor:
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS students (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100),
            password VARCHAR(75),
            class INT,
            major VARCHAR(100)
        )
        """)
        
        cursor.execute(
            query,
            fields
        )

        if fetch:
            return cursor.fetchall()

        db.commit()