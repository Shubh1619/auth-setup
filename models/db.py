import os
import psycopg2
from psycopg2.extras import RealDictCursor

# Load the database URL from environment or set default for local testing
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@localhost/dbname")

def get_db_connection():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)

def create_users_table():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        name VARCHAR(100) NOT NULL,
                        email VARCHAR(100) UNIQUE NOT NULL,
                        password VARCHAR(100) NOT NULL,
                        mobile VARCHAR(20) UNIQUE NOT NULL,
                        role VARCHAR(20) NOT NULL
                    );
                """)
                conn.commit()
                print("✅ users table created or already exists.")
    except Exception as e:
        print("❌ Error creating users table:", e)

print("DB URL used:", DATABASE_URL)

if __name__ == "__main__":
    create_users_table()
