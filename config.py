from pydantic import BaseModel, Field, validator, root_validator
from typing import List, Dict, Optional, Set, Any, Union
import os
import yaml
import toml
import json
from pathlib import Path
import logging
import hashlib
import hmac
from datetime import datetime

logger = logging.getLogger("TelegramSnowballSampler")

class ApiConfig(BaseModel):
    """Telegram API configuration"""
    api_id: int = Field(..., description="Telegram API ID")
    api_hash: str = Field(..., description="Telegram API hash")
    phone: str = Field(..., description="Phone number in international format")
    session_name: str = Field("anon", description="Session name, will be stored as {session_name}.session")
    
    @validator('api_hash')
    def validate_api_hash(cls, v):
        if not v or len(v) < 8:
            raise ValueError("API hash too short, please check your credentials")
        return v
    
    @validator('phone')
    def validate_phone(cls, v):
        # Remove spaces and ensure it starts with +
        v = v.replace(" ", "")
        if not v.startswith("+"):
            v = "+" + v
        return v

class SamplingConfig(BaseModel):
    """Snowball sampling configuration"""
    seed_channels: List[Union[int, str]] = Field(
        ..., 
        description="List of seed channels (can be usernames or channel IDs)"
    )
    max_channels: int = Field(
        1000, 
        description="Maximum number of channels to process",
        ge=1
    )
    mention_threshold: int = Field(
        1, 
        description="Minimum mentions required to add a channel to the queue",
        ge=1
    )
    max_mentions_per_channel: int = Field(
        100, 
        description="Maximum number of mentions to process per channel",
        ge=1
    )
    skip_processed_channels: bool = Field(
        True, 
        description="Skip channels that have already been processed"
    )
    max_concurrent_tasks: int = Field(
        5, 
        description="Maximum number of concurrent tasks",
        ge=1, le=50
    )
    
    @validator('seed_channels')
    def validate_seed_channels(cls, v):
        if not v:
            raise ValueError("At least one seed channel is required")
        
        # Convert numeric strings to integers when possible
        result = []
        for channel in v:
            if isinstance(channel, str) and channel.isdigit():
                result.append(int(channel))
            else:
                result.append(channel)
        return result

class PersistenceConfig(BaseModel):
    """Data persistence configuration"""
    enable: bool = Field(True, description="Enable data persistence")
    db_path: str = Field("data/sampler.db", description="Path to SQLite database file")
    save_interval: int = Field(
        60, 
        description="Interval in seconds between state saves",
        ge=10, le=3600
    )
    
    @validator('db_path')
    def validate_db_path(cls, v):
        # Ensure path has .db extension
        if not v.endswith('.db'):
            v += '.db'
        
        # Ensure directory exists
        db_dir = os.path.dirname(v)
        if db_dir and not os.path.exists(db_dir):
            try:
                os.makedirs(db_dir, exist_ok=True)
            except Exception as e:
                logger.warning(f"Could not create directory for database: {e}")
        
        return v

class CacheConfig(BaseModel):
    """Cache configuration"""
    enable: bool = Field(True, description="Enable caching")
    cache_dir: str = Field("data/cache", description="Directory to store cache files")
    max_age: int = Field(
        86400, 
        description="Maximum age of cache items in seconds (24 hours by default)",
        ge=60, le=31536000  # 1 minute to 1 year
    )
    
    @validator('cache_dir')
    def validate_cache_dir(cls, v):
        # Ensure directory exists
        if not os.path.exists(v):
            try:
                os.makedirs(v, exist_ok=True)
            except Exception as e:
                logger.warning(f"Could not create cache directory: {e}")
        return v

class RateLimitConfig(BaseModel):
    """Rate limiting configuration"""
    max_requests_per_second: float = Field(
        2.0, 
        description="Maximum requests per second",
        ge=0.1, le=20.0
    )
    retry_delay: int = Field(
        5, 
        description="Base delay in seconds before retrying after a rate limit",
        ge=1, le=300
    )
    max_retries: int = Field(
        5, 
        description="Maximum number of retries for rate-limited requests",
        ge=1, le=20
    )
    backoff_factor: float = Field(
        1.5, 
        description="Factor by which to increase delay after each retry",
        ge=1.0, le=5.0
    )

class LoggingConfig(BaseModel):
    """Logging configuration"""
    level: str = Field(
        "INFO", 
        description="Logging level"
    )
    log_to_file: bool = Field(False, description="Enable logging to file")
    log_file: Optional[str] = Field(None, description="Path to log file")
    
    @validator('level')
    def validate_level(cls, v):
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        v = v.upper()
        if v not in valid_levels:
            raise ValueError(f"Invalid log level: {v}. Must be one of {valid_levels}")
        return v
    
    @validator('log_file')
    def validate_log_file(cls, v, values):
        if values.get('log_to_file', False) and not v:
            # Default log file
            v = "data/logs/sampler.log"
        
        if v:
            # Ensure directory exists
            log_dir = os.path.dirname(v)
            if log_dir and not os.path.exists(log_dir):
                try:
                    os.makedirs(log_dir, exist_ok=True)
                except Exception as e:
                    logger.warning(f"Could not create directory for log file: {e}")
        
        return v

class SecurityConfig(BaseModel):
    """Security configuration for the application"""
    enable_hmac: bool = Field(
        True, 
        description="Enable HMAC verification for API requests"
    )
    api_salt: str = Field(
        "telegram_snowball_sampler_v2", 
        description="Salt used for HMAC generation"
    )
    token_ttl: int = Field(
        300, 
        description="Time-to-live for security tokens in seconds",
        ge=60, le=3600
    )
    encryption_key_rotation: bool = Field(
        True,
        description="Whether to rotate encryption keys periodically"
    )
    rotation_interval_days: int = Field(
        7,
        description="Days between encryption key rotations",
        ge=1, le=365
    )
    
    @validator('api_salt')
    def validate_api_salt(cls, v):
        if not v or len(v) < 8:
            raise ValueError("API salt too short, must be at least 8 characters")
        return v
    
    def generate_hmac_token(self, message: str) -> str:
        """Generate an HMAC token for the given message"""
        key = hashlib.sha256(self.api_salt.encode()).digest()
        return hmac.new(
            key=key,
            msg=message.encode(),
            digestmod=hashlib.sha256
        ).hexdigest()
    
    def verify_hmac_token(self, message: str, token: str) -> bool:
        """Verify an HMAC token for the given message"""
        expected_token = self.generate_hmac_token(message)
        return hmac.compare_digest(token, expected_token)

class ElasticsearchConfig(BaseModel):
    enabled: bool = False
    export_type: str = "filebeat"  # 'filebeat' or 'logstash'
    index_name: str = "tg_snowball_sampler"
    hosts: List[str] = ["localhost:9200"]
    username: Optional[str] = None
    password: Optional[str] = None
    ssl_enabled: bool = False
    export_dir: str = "elasticsearch_export"
    # Additional ES-specific settings
    document_type: str = "channel"
    template_enabled: bool = True

class Config(BaseModel):
    """Main configuration"""
    api: ApiConfig
    sampling: SamplingConfig
    persistence: PersistenceConfig = Field(default_factory=PersistenceConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    elasticsearch: ElasticsearchConfig = ElasticsearchConfig()
    
    config_version: int = Field(1, description="Configuration schema version")
    last_updated: datetime = Field(default_factory=datetime.now)
    
    class Config:
        """Pydantic config"""
        validate_assignment = True
        extra = "forbid"
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
    
    @root_validator
    def ensure_valid_configuration(cls, values):
        """Additional validation that spans multiple fields"""
        return values
    
    def to_dict(self):
        """Convert to dictionary"""
        return self.dict()
    
    def to_json(self):
        """Convert to JSON string"""
        return self.json(indent=2)
    
    def to_yaml(self):
        """Convert to YAML string"""
        return yaml.dump(json.loads(self.json()))
    
    def save(self, config_path: str):
        """Save configuration to file"""
        # Update timestamp
        self.last_updated = datetime.now()
        
        # Ensure directory exists
        config_dir = os.path.dirname(config_path)
        if config_dir and not os.path.exists(config_dir):
            os.makedirs(config_dir, exist_ok=True)
        
        # Detect format from extension
        if config_path.endswith('.yaml') or config_path.endswith('.yml'):
            with open(config_path, 'w') as f:
                f.write(self.to_yaml())
        elif config_path.endswith('.json'):
            with open(config_path, 'w') as f:
                f.write(self.to_json())
        else:
            # Default to YAML
            with open(config_path, 'w') as f:
                f.write(self.to_yaml())
        
        logger.info(f"Configuration saved to {config_path}")
        
    @classmethod
    def load(cls, config_path: str):
        """Load configuration from file"""
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        # Detect format from extension
        if config_path.endswith('.yaml') or config_path.endswith('.yml'):
            with open(config_path, 'r') as f:
                data = yaml.safe_load(f)
        elif config_path.endswith('.json'):
            with open(config_path, 'r') as f:
                data = json.load(f)
        else:
            # Try YAML first
            try:
                with open(config_path, 'r') as f:
                    data = yaml.safe_load(f)
            except:
                # Try JSON
                with open(config_path, 'r') as f:
                    data = json.load(f)
        
        config = cls(**data)
        logger.info(f"Configuration loaded from {config_path}")
        return config

def get_config_hash(config):
    """Generate a unique hash for the given configuration"""
    serialized = json.dumps(config.dict(), sort_keys=True).encode()
    return hashlib.sha256(serialized).hexdigest()[:16]

def create_default_config():
    """Create a default configuration instance"""
    return Config(
        api=ApiConfig(
            api_id=0,  # Must be changed by user
            api_hash="your_api_hash_here",  # Must be changed by user
            phone="+1234567890",  # Must be changed by user
            session_name="tg_sampler"
        ),
        sampling=SamplingConfig(
            seed_channels=["telegram"],  # Example seed
            max_channels=1000,
            mention_threshold=2,
            max_mentions_per_channel=100,
            skip_processed_channels=True,
            max_concurrent_tasks=5
        )
    )

def load_config(config_path="config.yaml"):
    """Load configuration or create default if not exists"""
    try:
        return Config.load(config_path)
    except FileNotFoundError:
        # Create default config
        config = create_default_config()
        config.save(config_path)
        logger.info(f"Default configuration created at {config_path}")
        logger.warning("Please update the API credentials before running!")
        return config
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        raise

def save_config(config: Config, config_path: str = "config.yaml", format: str = "yaml"):
    """
    Save configuration to a file
    
    Args:
        config: Configuration object
        config_path: Path to save the configuration file
        format: Format to save the configuration in (yaml, toml, json)
    """
    # Convert config to dict
    config_dict = config.dict()
    
    try:
        if format.lower() == 'yaml':
            with open(config_path, 'w') as f:
                yaml.dump(config_dict, f, default_flow_style=False)
        elif format.lower() == 'toml':
            with open(config_path, 'w') as f:
                toml.dump(config_dict, f)
        elif format.lower() == 'json':
            with open(config_path, 'w') as f:
                json.dump(config_dict, f, indent=2)
        else:
            logger.warning(f"Unsupported format: {format}, using YAML")
            with open(config_path, 'w') as f:
                yaml.dump(config_dict, f, default_flow_style=False)
                
        logger.info(f"Configuration saved to {config_path}")
    except Exception as e:
        logger.error(f"Failed to save configuration to {config_path}: {e}")

def create_default_config(config_path: str = "config.yaml", format: str = "yaml"):
    """
    Create a default configuration file
    
    Args:
        config_path: Path to save the configuration file
        format: Format to save the configuration in (yaml, toml, json)
    """
    # Create default config
    config = Config(
        api=ApiConfig(
            api_id=0,  # Must be changed by user
            api_hash="your_api_hash_here",  # Must be changed by user
            phone="+1234567890",  # Must be changed by user
            session_name="tg_sampler"
        ),
        sampling=SamplingConfig(
            seed_channels=["telegram"],  # Example seed
            max_channels=1000,
            mention_threshold=2,
            max_mentions_per_channel=100,
            skip_processed_channels=True,
            max_concurrent_tasks=5
        )
    )
    
    # Save config
    save_config(config, config_path, format)
    return config

if __name__ == "__main__":
    # Create default configuration file
    config = create_default_config()
    print("Created default configuration file: config.yaml") 