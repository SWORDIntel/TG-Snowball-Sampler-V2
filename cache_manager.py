import diskcache
import hashlib
import time
import random
import logging
import threading
import os
import json
from typing import Any, Dict, Optional, Callable, List
from tenacity import retry, wait_exponential, stop_after_attempt, retry_if_exception_type
from functools import wraps
from config import CacheConfig, RateLimitConfig

logger = logging.getLogger("CacheManager")

class CacheManager:
    """
    Manager for caching API responses and managing rate limits.
    Provides disk-based caching with TTL and advanced rate limiting.
    """
    
    def __init__(self, cache_config: CacheConfig, rate_limit_config: RateLimitConfig):
        """
        Initialize cache manager
        
        Args:
            cache_config: Cache configuration
            rate_limit_config: Rate limit configuration
        """
        self.config = cache_config
        self.rate_limit_config = rate_limit_config
        self._cache = None
        self._api_request_times = {}  # Track request times per API key
        self._lock = threading.RLock()
        
        if self.config.enabled:
            self._initialize_cache()
    
    def _initialize_cache(self):
        """Initialize the disk cache"""
        if self.config.enabled:
            cache_dir = self.config.cache_dir
            
            # Create cache directory if it doesn't exist
            if not os.path.exists(cache_dir):
                os.makedirs(cache_dir)
            
            # Initialize disk cache
            self._cache = diskcache.Cache(
                cache_dir,
                size_limit=self.config.max_cache_size_mb * 1024 * 1024  # Convert MB to bytes
            )
            
            logger.info(f"Initialized cache in {cache_dir} with {self.config.max_cache_size_mb}MB limit")
    
    def _get_cache_key(self, key: str) -> str:
        """Generate a deterministic cache key"""
        return hashlib.md5(str(key).encode()).hexdigest()
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a value from the cache
        
        Args:
            key: Cache key
            default: Default value if key not found
            
        Returns:
            Cached value or default
        """
        if not self.config.enabled or not self._cache:
            return default
        
        cache_key = self._get_cache_key(key)
        
        try:
            value = self._cache.get(cache_key, default=default)
            if value is not default:
                logger.debug(f"Cache hit for key: {key}")
                return value
        except Exception as e:
            logger.warning(f"Cache get error for key {key}: {e}")
        
        logger.debug(f"Cache miss for key: {key}")
        return default
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """
        Set a value in the cache
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds, uses default from config if None
            
        Returns:
            True if successful, False otherwise
        """
        if not self.config.enabled or not self._cache:
            return False
        
        cache_key = self._get_cache_key(key)
        
        if ttl is None:
            ttl = self.config.ttl_seconds
        
        try:
            self._cache.set(cache_key, value, expire=ttl)
            logger.debug(f"Cached value for key: {key}, TTL: {ttl}s")
            return True
        except Exception as e:
            logger.warning(f"Cache set error for key {key}: {e}")
            return False
    
    def delete(self, key: str) -> bool:
        """
        Delete a value from the cache
        
        Args:
            key: Cache key
            
        Returns:
            True if successful, False otherwise
        """
        if not self.config.enabled or not self._cache:
            return False
        
        cache_key = self._get_cache_key(key)
        
        try:
            self._cache.delete(cache_key)
            logger.debug(f"Deleted cache for key: {key}")
            return True
        except Exception as e:
            logger.warning(f"Cache delete error for key {key}: {e}")
            return False
    
    def clear(self):
        """Clear the entire cache"""
        if not self.config.enabled or not self._cache:
            return
        
        try:
            self._cache.clear()
            logger.info("Cache cleared")
        except Exception as e:
            logger.warning(f"Cache clear error: {e}")
    
    def close(self):
        """Close the cache connection"""
        if self._cache:
            try:
                self._cache.close()
                logger.debug("Cache closed")
            except Exception as e:
                logger.warning(f"Cache close error: {e}")
    
    def stats(self) -> Dict[str, Any]:
        """
        Get cache statistics
        
        Returns:
            Dictionary of cache statistics
        """
        if not self.config.enabled or not self._cache:
            return {"enabled": False}
        
        try:
            stats = {
                "enabled": True,
                "size": self._cache.size,
                "size_limit": self._cache.size_limit,
                "directory": self._cache.directory,
                "item_count": len(self._cache),
            }
            return stats
        except Exception as e:
            logger.warning(f"Cache stats error: {e}")
            return {"enabled": True, "error": str(e)}
    
    def cache_api_response(self, ttl: Optional[int] = None):
        """
        Decorator for caching API responses
        
        Args:
            ttl: Time to live in seconds, uses default from config if None
        """
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                if not self.config.enabled:
                    return await func(*args, **kwargs)
                
                # Generate cache key based on function name and arguments
                cache_key = f"{func.__name__}:{hash(str(args))}-{hash(str(kwargs))}"
                
                # Check cache
                cached_result = self.get(cache_key)
                if cached_result is not None:
                    return cached_result
                
                # Call function
                result = await func(*args, **kwargs)
                
                # Cache result
                self.set(cache_key, result, ttl)
                
                return result
            return wrapper
        return decorator
    
    def rate_limited(self, api_id: str = None):
        """
        Decorator for rate limiting API calls
        
        Args:
            api_id: Optional API ID to use for rate limiting, if None uses the first argument
        """
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Get API ID
                actual_api_id = api_id
                if actual_api_id is None and len(args) > 0:
                    actual_api_id = str(args[0])
                
                # Apply rate limiting
                self._apply_rate_limit(actual_api_id)
                
                # Add retry with exponential backoff for rate limit errors
                @retry(
                    retry=retry_if_exception_type((Exception,)),
                    wait=wait_exponential(
                        multiplier=self.rate_limit_config.initial_backoff_time,
                        max=self.rate_limit_config.max_backoff_time,
                        exp_base=self.rate_limit_config.backoff_factor
                    ),
                    stop=stop_after_attempt(5)
                )
                async def retry_func():
                    try:
                        return await func(*args, **kwargs)
                    except Exception as e:
                        # Check if this is a rate limit error
                        if "flood" in str(e).lower() or "rate" in str(e).lower() or "limit" in str(e).lower():
                            # Record rate limit hit
                            self._record_rate_limit(actual_api_id)
                            logger.warning(f"Rate limit hit for API ID {actual_api_id}: {e}")
                        raise
                
                try:
                    return await retry_func()
                except Exception as e:
                    # Record the API call even if it failed
                    self._record_api_call(actual_api_id)
                    raise
            
            return wrapper
        return decorator
    
    def _apply_rate_limit(self, api_id: str):
        """
        Apply rate limiting for an API ID
        
        Args:
            api_id: API ID to apply rate limiting for
        """
        with self._lock:
            if api_id not in self._api_request_times:
                self._api_request_times[api_id] = []
            
            # Clean up old requests
            now = time.time()
            self._api_request_times[api_id] = [
                t for t in self._api_request_times[api_id] 
                if now - t < 1.0  # Keep requests from the last second
            ]
            
            # Check rate limit
            if len(self._api_request_times[api_id]) >= self.rate_limit_config.max_requests_per_second:
                # Calculate wait time
                wait_time = 1.0 / self.rate_limit_config.max_requests_per_second
                
                # Add jitter if enabled
                if self.rate_limit_config.jitter:
                    wait_time *= (1.0 + random.random() * 0.1)  # Add up to 10% jitter
                
                logger.debug(f"Rate limiting API ID {api_id}, waiting {wait_time:.2f}s")
                time.sleep(wait_time)
            
            # Record request time
            self._api_request_times[api_id].append(now)
    
    def _record_api_call(self, api_id: str):
        """
        Record an API call for an API ID
        
        Args:
            api_id: API ID to record call for
        """
        with self._lock:
            if api_id not in self._api_request_times:
                self._api_request_times[api_id] = []
            
            self._api_request_times[api_id].append(time.time())
    
    def _record_rate_limit(self, api_id: str):
        """
        Record a rate limit hit for an API ID
        
        Args:
            api_id: API ID to record rate limit for
        """
        # This should be implemented to store rate limit information in a persistent store
        # For now, just log it
        logger.warning(f"Rate limit hit for API ID {api_id}")
    
    def __del__(self):
        """Cleanup on deletion"""
        self.close()


# Helper function to create a cache manager from config
def create_cache_manager(cache_config: CacheConfig, rate_limit_config: RateLimitConfig) -> CacheManager:
    """
    Create a cache manager from configuration
    
    Args:
        cache_config: Cache configuration
        rate_limit_config: Rate limit configuration
        
    Returns:
        CacheManager instance
    """
    return CacheManager(cache_config, rate_limit_config)


if __name__ == "__main__":
    # Example usage
    from config import CacheConfig, RateLimitConfig
    import asyncio
    
    # Configure logging
    logging.basicConfig(level=logging.DEBUG)
    
    # Create cache manager
    cache_config = CacheConfig(
        enabled=True,
        ttl_seconds=60,
        max_cache_size_mb=10,
        cache_dir="test_cache"
    )
    
    rate_limit_config = RateLimitConfig(
        max_requests_per_second=2.0,
        backoff_factor=1.5,
        max_backoff_time=10,
        initial_backoff_time=1,
        jitter=True
    )
    
    cache_manager = create_cache_manager(cache_config, rate_limit_config)
    
    # Example of caching
    @cache_manager.cache_api_response(ttl=60)
    async def expensive_operation(param: str):
        print(f"Performing expensive operation with param: {param}")
        await asyncio.sleep(1)  # Simulate work
        return f"Result for {param}"
    
    # Example of rate limiting
    @cache_manager.rate_limited(api_id="test_api")
    async def api_call(param: str):
        print(f"Making API call with param: {param}")
        await asyncio.sleep(0.1)  # Simulate API call
        return f"API result for {param}"
    
    async def run_tests():
        # Test caching
        print("Testing caching...")
        for i in range(3):
            result = await expensive_operation("test")
            print(f"Result: {result}")
        
        # Test rate limiting
        print("\nTesting rate limiting...")
        for i in range(10):
            start = time.time()
            result = await api_call(f"test_{i}")
            elapsed = time.time() - start
            print(f"Call {i} took {elapsed:.2f}s, result: {result}")
        
        # Print cache stats
        print("\nCache stats:")
        print(json.dumps(cache_manager.stats(), indent=2))
        
        # Cleanup
        cache_manager.close()
        import shutil
        shutil.rmtree("test_cache")
    
    # Run tests
    asyncio.run(run_tests()) 