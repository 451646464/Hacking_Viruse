"""
Script to add api_key column to users table
Run this once to update the database schema
"""
from app import app, db
from sqlalchemy import text

def add_api_key_column():
    with app.app_context():
        try:
            # Check if column already exists
            result = db.session.execute(text("PRAGMA table_info(users)"))
            columns = [row[1] for row in result]
            
            if 'api_key' not in columns:
                print("Adding api_key column to users table...")
                # SQLite doesn't support adding UNIQUE constraint in ALTER TABLE
                # So we add the column without UNIQUE, it will be unique by application logic
                db.session.execute(text('ALTER TABLE users ADD COLUMN api_key VARCHAR(64)'))
                db.session.commit()
                print("✓ Successfully added api_key column!")
                print("Note: UNIQUE constraint will be enforced by application logic")
            else:
                print("✓ api_key column already exists")
                
        except Exception as e:
            print(f"✗ Error: {str(e)}")
            db.session.rollback()

if __name__ == '__main__':
    add_api_key_column()
