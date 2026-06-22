from sqlalchemy import create_engine, text
import os

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg2://postgres:root123@localhost:5432/abuse_moderation"
)

engine = create_engine(DATABASE_URL)

def migrate():
    """Add deleted_posts table for post deletion notifications"""
    with engine.connect() as conn:
        try:
            print("Starting migration to add deleted_posts table...")
            
            # Create deleted_posts table
            print("Creating deleted_posts table...")
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS deleted_posts (
                    id SERIAL PRIMARY KEY,
                    original_post_id INTEGER NOT NULL,
                    content TEXT NOT NULL,
                    author_id INTEGER NOT NULL REFERENCES users(id),
                    deleted_by INTEGER NOT NULL REFERENCES users(id),
                    deletion_reason VARCHAR NOT NULL,
                    deleted_at TIMESTAMP DEFAULT NOW(),
                    viewed BOOLEAN DEFAULT FALSE
                )
            """))
            print("✓ Created deleted_posts table")
            
            # Create indexes
            print("Creating indexes...")
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_deleted_posts_author 
                ON deleted_posts(author_id)
            """))
            
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_deleted_posts_viewed 
                ON deleted_posts(viewed)
            """))
            print("✓ Created indexes")
            
            conn.commit()
            print("\n✅ Migration completed successfully!")
            print("Post deletion feature is now available.")
            
        except Exception as e:
            print(f"\n❌ Migration failed: {e}")
            conn.rollback()

if __name__ == "__main__":
    migrate()