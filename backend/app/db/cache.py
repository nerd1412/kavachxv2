import time
from typing import Any, Dict

class SimpleConfigCache:
    """A lightweight async-safe memory cache for dashboard/stats endpoints."""
    def __init__(self, ttl: int = 10):
        self.ttl = ttl
        self._cache: Dict[str, Dict[str, Any]] = {}
        
    async def get(self, key: str) -> Any:
        entry = self._cache.get(key)
        if entry:
            if time.time() - entry["timestamp"] < self.ttl:
                return entry["data"]
            else:
                del self._cache[key]
        return None
        
    async def set(self, key: str, value: Any):
        self._cache[key] = {
            "timestamp": time.time(),
            "data": value
        }
        
    def invalidate(self, key: str):
        if key in self._cache:
            del self._cache[key]

# Global singleton
dashboard_cache = SimpleConfigCache(ttl=5) # 5 seconds caching for fast but throttled requests
