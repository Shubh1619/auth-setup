import os
import psycopg2
from psycopg2.extras import RealDictCursor

# Add sslmode=require to the connection URL
DATABASE_URL = os.getenv(
    "DATABASE_URL"
)

def get_db_connection():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)

def create_users_table():
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(100),
                    email VARCHAR(100) UNIQUE,
                    password VARCHAR(100),
                    mobile VARCHAR(20) UNIQUE
                )
            """)
            connection.commit()
    finally:
        connection.close()
