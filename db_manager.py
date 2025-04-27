import sqlite3
import json
import os
import time
import pickle
from typing import Dict, Set, List, Any, Optional, Tuple, Union, Deque
from collections import deque
from contextlib import contextmanager
import threading
from datetime import datetime
import hashlib
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
import logging
import tabulate
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("DBManager")

# Database schema version
SCHEMA_VERSION = "1.0.0"

class Database:
    """Low-level database connection and schema management"""
    
    SCHEMA_VERSION = 1
    
    def __init__(self, db_path: str):
        """Initialize the database connection"""
        self.db_path = db_path
        self.conn = None
        self.lock = threading.RLock()
        self._initialize_db()
    
    def _initialize_db(self):
        """Initialize the database, creating it if it doesn't exist"""
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            try:
                os.makedirs(db_dir, exist_ok=True)
                logger.info(f"Created directory for database: {db_dir}")
            except Exception as e:
                logger.error(f"Failed to create directory for database: {e}")
                raise
        
        # Connect to the database
        self._connect()
        
        # Check if the schema needs to be created or upgraded
        with self.lock:
            try:
                cursor = self.conn.cursor()
                
                # Check if the schema_version table exists
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'")
                if not cursor.fetchone():
                    # Create the schema version table
                    cursor.execute("CREATE TABLE schema_version (version INTEGER)")
                    cursor.execute("INSERT INTO schema_version VALUES (?)", (self.SCHEMA_VERSION,))
                    
                    # Create the initial schema
                    self._create_schema()
                    logger.info(f"Created new database schema (version {self.SCHEMA_VERSION})")
                else:
                    # Check the schema version
                    cursor.execute("SELECT version FROM schema_version")
                    current_version = cursor.fetchone()[0]
                    
                    if current_version < self.SCHEMA_VERSION:
                        # Upgrade the schema
                        self._upgrade_schema(current_version)
                        
                        # Update the schema version
                        cursor.execute("UPDATE schema_version SET version = ?", (self.SCHEMA_VERSION,))
                        logger.info(f"Upgraded database schema from version {current_version} to {self.SCHEMA_VERSION}")
                
                self.conn.commit()
            except Exception as e:
                logger.error(f"Error initializing database: {e}")
                if self.conn:
                    self.conn.rollback()
                raise
    
    def _connect(self):
        """Connect to the SQLite database"""
        try:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            # Enable foreign keys
            self.conn.execute("PRAGMA foreign_keys = ON")
            # Use Row as row factory to get column names
            self.conn.row_factory = sqlite3.Row
            logger.debug(f"Connected to database: {self.db_path}")
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            raise
    
    def _create_schema(self):
        """Create the initial database schema"""
        cursor = self.conn.cursor()
        
        # Channel queue table
        cursor.execute("""
        CREATE TABLE channel_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            channel_id TEXT NOT NULL,
            channel_name TEXT,
            mentions INTEGER DEFAULT 1,
            first_seen_timestamp REAL,
            priority INTEGER DEFAULT 0,
            UNIQUE(channel_id)
        )
        """)
        
        # Processed channels table
        cursor.execute("""
        CREATE TABLE processed_channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            channel_id TEXT NOT NULL,
            channel_name TEXT,
            processed_timestamp REAL,
            mentions_found INTEGER DEFAULT 0,
            source_channel_id TEXT,
            UNIQUE(channel_id)
        )
        """)
        
        # Channel metadata table
        cursor.execute("""
        CREATE TABLE channel_metadata (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            channel_id TEXT NOT NULL,
            channel_name TEXT,
            title TEXT,
            username TEXT,
            description TEXT,
            member_count INTEGER,
            message_count INTEGER,
            is_verified BOOLEAN,
            is_restricted BOOLEAN,
            last_updated REAL,
            raw_data TEXT,
            UNIQUE(channel_id)
        )
        """)
        
        # Mentions table
        cursor.execute("""
        CREATE TABLE mentions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_channel_id TEXT NOT NULL,
            target_channel_id TEXT NOT NULL,
            mention_count INTEGER DEFAULT 1,
            first_seen_timestamp REAL,
            last_seen_timestamp REAL,
            UNIQUE(source_channel_id, target_channel_id)
        )
        """)
        
        # Sampling state table
        cursor.execute("""
        CREATE TABLE sampling_state (
            id INTEGER PRIMARY KEY,
            state_key TEXT NOT NULL,
            state_value BLOB,
            last_updated REAL,
            UNIQUE(state_key)
        )
        """)
        
        # Create indices for better performance
        cursor.execute("CREATE INDEX idx_channel_queue_channel_id ON channel_queue(channel_id)")
        cursor.execute("CREATE INDEX idx_processed_channels_channel_id ON processed_channels(channel_id)")
        cursor.execute("CREATE INDEX idx_channel_metadata_channel_id ON channel_metadata(channel_id)")
        cursor.execute("CREATE INDEX idx_mentions_source ON mentions(source_channel_id)")
        cursor.execute("CREATE INDEX idx_mentions_target ON mentions(target_channel_id)")
        
        self.conn.commit()
    
    def _upgrade_schema(self, current_version: int):
        """Upgrade the database schema from current_version to SCHEMA_VERSION"""
        # Implementation for future schema upgrades
        cursor = self.conn.cursor()
        
        # Example upgrade from version 1 to 2
        if current_version == 1 and self.SCHEMA_VERSION >= 2:
            # Add new columns or tables as needed
            # cursor.execute("ALTER TABLE channel_metadata ADD COLUMN category TEXT")
            # Create new tables if needed
            pass
        
        # Add more upgrade paths as needed
        
        self.conn.commit()
    
    def execute(self, query: str, params: tuple = ()):
        """Execute a SQL query with the given parameters"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute(query, params)
                return cursor
            except Exception as e:
                logger.error(f"Error executing query: {e}\nQuery: {query}\nParams: {params}")
                self.conn.rollback()
                raise
    
    def executemany(self, query: str, params_list: list):
        """Execute a SQL query with multiple parameter sets"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.executemany(query, params_list)
                return cursor
            except Exception as e:
                logger.error(f"Error executing query with multiple parameters: {e}\nQuery: {query}")
                self.conn.rollback()
                raise
    
    def commit(self):
        """Commit the current transaction"""
        with self.lock:
            try:
                self.conn.commit()
            except Exception as e:
                logger.error(f"Error committing transaction: {e}")
                self.conn.rollback()
                raise
    
    def close(self):
        """Close the database connection"""
        with self.lock:
            if self.conn:
                try:
                    self.conn.close()
                    logger.debug(f"Closed database connection: {self.db_path}")
                except Exception as e:
                    logger.error(f"Error closing database connection: {e}")


class DBManager:
    """High-level database operations for the Telegram Snowball Sampler"""
    
    def __init__(self, db_path: str):
        """Initialize the database manager"""
        self.db = Database(db_path)
        logger.info(f"Initialized database manager with database at {db_path}")
    
    def save_channel_queue(self, channel_queue: Dict[str, Dict]):
        """Save the channel queue to the database"""
        if not channel_queue:
            return
        
        # Convert the channel queue to a list of tuples for batch insertion
        now = time.time()
        rows = []
        
        for channel_id, data in channel_queue.items():
            channel_name = data.get('name', '')
            mentions = data.get('mentions', 1)
            first_seen = data.get('first_seen', now)
            priority = data.get('priority', 0)
            
            rows.append((channel_id, channel_name, mentions, first_seen, priority))
        
        # Insert or update the channel queue
        query = """
        INSERT INTO channel_queue (channel_id, channel_name, mentions, first_seen_timestamp, priority)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(channel_id) DO UPDATE SET
            channel_name = excluded.channel_name,
            mentions = excluded.mentions,
            priority = excluded.priority
        """
        
        self.db.executemany(query, rows)
        self.db.commit()
        logger.debug(f"Saved {len(rows)} channels to the channel queue")
    
    def load_channel_queue(self) -> Dict[str, Dict]:
        """Load the channel queue from the database"""
        query = """
        SELECT channel_id, channel_name, mentions, first_seen_timestamp, priority
        FROM channel_queue
        ORDER BY priority DESC, mentions DESC
        """
        
        cursor = self.db.execute(query)
        channel_queue = {}
        
        for row in cursor.fetchall():
            channel_id = row['channel_id']
            channel_queue[channel_id] = {
                'name': row['channel_name'],
                'mentions': row['mentions'],
                'first_seen': row['first_seen_timestamp'],
                'priority': row['priority']
            }
        
        logger.debug(f"Loaded {len(channel_queue)} channels from the channel queue")
        return channel_queue
    
    def add_processed_channel(self, channel_id: str, channel_name: str = "", mentions_found: int = 0, source_channel_id: str = None):
        """Add a channel to the processed channels list"""
        now = time.time()
        
        query = """
        INSERT INTO processed_channels (channel_id, channel_name, processed_timestamp, mentions_found, source_channel_id)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(channel_id) DO UPDATE SET
            channel_name = excluded.channel_name,
            processed_timestamp = excluded.processed_timestamp,
            mentions_found = excluded.mentions_found,
            source_channel_id = excluded.source_channel_id
        """
        
        self.db.execute(query, (channel_id, channel_name, now, mentions_found, source_channel_id))
        self.db.commit()
        logger.debug(f"Added channel {channel_id} to processed channels")
    
    def is_channel_processed(self, channel_id: str) -> bool:
        """Check if a channel has been processed"""
        query = "SELECT 1 FROM processed_channels WHERE channel_id = ?"
        cursor = self.db.execute(query, (channel_id,))
        return cursor.fetchone() is not None
    
    def get_processed_channels(self) -> Set[str]:
        """Get the set of processed channel IDs"""
        query = "SELECT channel_id FROM processed_channels"
        cursor = self.db.execute(query)
        return {row['channel_id'] for row in cursor.fetchall()}
    
    def save_channel_metadata(self, channel_id: str, metadata: Dict):
        """Save metadata for a channel"""
        now = time.time()
        
        # Extract basic metadata fields
        channel_name = metadata.get('name', '')
        title = metadata.get('title', '')
        username = metadata.get('username', '')
        description = metadata.get('description', '')
        member_count = metadata.get('member_count', 0)
        message_count = metadata.get('message_count', 0)
        is_verified = bool(metadata.get('verified', False))
        is_restricted = bool(metadata.get('restricted', False))
        
        # Store the full metadata as JSON
        raw_data = json.dumps(metadata)
        
        query = """
        INSERT INTO channel_metadata (
            channel_id, channel_name, title, username, description, 
            member_count, message_count, is_verified, is_restricted, 
            last_updated, raw_data
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(channel_id) DO UPDATE SET
            channel_name = excluded.channel_name,
            title = excluded.title,
            username = excluded.username,
            description = excluded.description,
            member_count = excluded.member_count,
            message_count = excluded.message_count,
            is_verified = excluded.is_verified,
            is_restricted = excluded.is_restricted,
            last_updated = excluded.last_updated,
            raw_data = excluded.raw_data
        """
        
        self.db.execute(query, (
            channel_id, channel_name, title, username, description,
            member_count, message_count, is_verified, is_restricted,
            now, raw_data
        ))
        self.db.commit()
        logger.debug(f"Saved metadata for channel {channel_id}")
    
    def get_channel_metadata(self, channel_id: str) -> Optional[Dict]:
        """Get metadata for a channel"""
        query = "SELECT raw_data FROM channel_metadata WHERE channel_id = ?"
        cursor = self.db.execute(query, (channel_id,))
        row = cursor.fetchone()
        
        if row:
            try:
                return json.loads(row['raw_data'])
            except json.JSONDecodeError:
                logger.error(f"Error decoding JSON metadata for channel {channel_id}")
                return None
        
        return None
    
    def add_mention(self, source_channel_id: str, target_channel_id: str):
        """Add or update a mention between channels"""
        now = time.time()
        
        query = """
        INSERT INTO mentions (source_channel_id, target_channel_id, mention_count, first_seen_timestamp, last_seen_timestamp)
        VALUES (?, ?, 1, ?, ?)
        ON CONFLICT(source_channel_id, target_channel_id) DO UPDATE SET
            mention_count = mention_count + 1,
            last_seen_timestamp = ?
        """
        
        self.db.execute(query, (source_channel_id, target_channel_id, now, now, now))
        self.db.commit()
    
    def get_mentions(self, source_channel_id: str = None) -> List[Dict]:
        """Get mentions, optionally filtered by source channel"""
        if source_channel_id:
            query = """
            SELECT source_channel_id, target_channel_id, mention_count, first_seen_timestamp, last_seen_timestamp
            FROM mentions
            WHERE source_channel_id = ?
            """
            cursor = self.db.execute(query, (source_channel_id,))
        else:
            query = """
            SELECT source_channel_id, target_channel_id, mention_count, first_seen_timestamp, last_seen_timestamp
            FROM mentions
            """
            cursor = self.db.execute(query)
        
        mentions = []
        for row in cursor.fetchall():
            mentions.append({
                'source': row['source_channel_id'],
                'target': row['target_channel_id'],
                'count': row['mention_count'],
                'first_seen': row['first_seen_timestamp'],
                'last_seen': row['last_seen_timestamp']
            })
        
        return mentions
    
    def save_sampling_state(self, state_key: str, state_value: Any):
        """Save a sampling state value"""
        now = time.time()
        
        # Serialize the state value
        serialized = pickle.dumps(state_value)
        
        query = """
        INSERT INTO sampling_state (state_key, state_value, last_updated)
        VALUES (?, ?, ?)
        ON CONFLICT(state_key) DO UPDATE SET
            state_value = excluded.state_value,
            last_updated = excluded.last_updated
        """
        
        self.db.execute(query, (state_key, serialized, now))
        self.db.commit()
        logger.debug(f"Saved sampling state for key: {state_key}")
    
    def load_sampling_state(self, state_key: str) -> Any:
        """Load a sampling state value"""
        query = "SELECT state_value FROM sampling_state WHERE state_key = ?"
        cursor = self.db.execute(query, (state_key,))
        row = cursor.fetchone()
        
        if row and row['state_value']:
            try:
                return pickle.loads(row['state_value'])
            except Exception as e:
                logger.error(f"Error deserializing sampling state for key {state_key}: {e}")
                return None
        
        return None
    
    def remove_sampling_state(self, state_key: str):
        """Remove a sampling state value"""
        query = "DELETE FROM sampling_state WHERE state_key = ?"
        self.db.execute(query, (state_key,))
        self.db.commit()
        logger.debug(f"Removed sampling state for key: {state_key}")
    
    def get_all_sampling_state_keys(self) -> List[str]:
        """Get all sampling state keys"""
        query = "SELECT state_key FROM sampling_state"
        cursor = self.db.execute(query)
        return [row['state_key'] for row in cursor.fetchall()]
    
    def save_full_state(self, channel_queue: Dict, channel_metadata: Dict, state: Dict):
        """Save the full sampling state"""
        # Begin transaction
        # Save channel queue
        self.save_channel_queue(channel_queue)
        
        # Save channel metadata
        for channel_id, metadata in channel_metadata.items():
            self.save_channel_metadata(channel_id, metadata)
        
        # Save other state values
        for key, value in state.items():
            self.save_sampling_state(key, value)
        
        self.db.commit()
        logger.info("Saved full sampling state to database")
    
    def load_full_state(self) -> Tuple[Dict, Dict, Dict]:
        """Load the full sampling state"""
        # Load channel queue
        channel_queue = self.load_channel_queue()
        
        # Load processed channels
        processed_channels = self.get_processed_channels()
        
        # Load metadata for all channels
        query = "SELECT channel_id, raw_data FROM channel_metadata"
        cursor = self.db.execute(query)
        
        channel_metadata = {}
        for row in cursor.fetchall():
            try:
                metadata = json.loads(row['raw_data'])
                channel_metadata[row['channel_id']] = metadata
            except json.JSONDecodeError:
                logger.error(f"Error decoding JSON metadata for channel {row['channel_id']}")
        
        # Load all other state values
        state_keys = self.get_all_sampling_state_keys()
        state = {}
        
        for key in state_keys:
            state[key] = self.load_sampling_state(key)
        
        # Add processed_channels to state
        state['processed_channels'] = processed_channels
        
        logger.info("Loaded full sampling state from database")
        return channel_queue, channel_metadata, state
    
    def dump_summary(self) -> Dict:
        """Dump a summary of the persisted state"""
        summary = {}
        
        # Count channels in queue
        query = "SELECT COUNT(*) as count FROM channel_queue"
        cursor = self.db.execute(query)
        summary['queue_size'] = cursor.fetchone()['count']
        
        # Count processed channels
        query = "SELECT COUNT(*) as count FROM processed_channels"
        cursor = self.db.execute(query)
        summary['processed_channels'] = cursor.fetchone()['count']
        
        # Count channels with metadata
        query = "SELECT COUNT(*) as count FROM channel_metadata"
        cursor = self.db.execute(query)
        summary['channels_with_metadata'] = cursor.fetchone()['count']
        
        # Count mentions
        query = "SELECT COUNT(*) as count FROM mentions"
        cursor = self.db.execute(query)
        summary['mentions'] = cursor.fetchone()['count']
        
        # Count sampling state keys
        query = "SELECT COUNT(*) as count FROM sampling_state"
        cursor = self.db.execute(query)
        summary['state_keys'] = cursor.fetchone()['count']
        
        # Get database file size
        if os.path.exists(self.db.db_path):
            summary['db_size'] = os.path.getsize(self.db.db_path)
        else:
            summary['db_size'] = 0
        
        return summary
    
    def clear_database(self):
        """Clear all data from the database"""
        tables = [
            'channel_queue',
            'processed_channels',
            'channel_metadata',
            'mentions',
            'sampling_state'
        ]
        
        for table in tables:
            query = f"DELETE FROM {table}"
            self.db.execute(query)
        
        self.db.commit()
        logger.warning("Cleared all data from the database")
    
    def close(self):
        """Close the database connection"""
        self.db.close()


def create_migration(migration_name):
    """
    Create a new database migration
    
    Args:
        migration_name: Name of the migration
    """
    # This would normally use alembic to create migration scripts
    # For simplicity, we just create a skeleton here
    migrations_dir = "migrations"
    
    if not os.path.exists(migrations_dir):
        os.makedirs(migrations_dir)
    
    timestamp = int(time.time())
    filename = f"{migrations_dir}/{timestamp}_{migration_name}.py"
    
    with open(filename, "w") as f:
        f.write(f"""
# Migration: {migration_name}
# Created: {datetime.now().isoformat()}

def upgrade(conn):
    # Add your upgrade logic here
    cursor = conn.cursor()
    # Example: cursor.execute("ALTER TABLE table_name ADD COLUMN new_column TEXT")
    conn.commit()

def downgrade(conn):
    # Add your downgrade logic here
    cursor = conn.cursor()
    # Example: cursor.execute("ALTER TABLE table_name DROP COLUMN new_column")
    conn.commit()
""")
    
    print(f"Created migration: {filename}")


if __name__ == "__main__":
    # Example usage
    db = DBManager("test_sampler_state.db")
    
    # Create test data
    db.save_queue(deque(["channel1", "channel2", "channel3"]))
    db.save_processed_channels(set(["channel4", "channel5"]))
    
    # Save test metadata
    db.save_channel_metadata("channel1", {
        "title": "Test Channel 1",
        "username": "testchannel1",
        "description": "This is a test channel",
        "member_count": 100,
        "category": "technology",
        "clickable_link": "https://t.me/testchannel1"
    })
    
    # Test cache
    db.set_cache("test_key", {"test": "value"}, 60)
    cached_value = db.get_cache("test_key")
    print(f"Cached value: {cached_value}")
    
    # Print state summary
    db.dump_state_summary()
    
    # Clean up
    os.remove("test_sampler_state.db") 