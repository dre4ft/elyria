"""
Lightweight TTL cache — no Redis dependency. Thread-safe, per-key TTL, auto-pruning.

Usage:
  from core.cache import cached

  @cached(ttl=30)
  def expensive_query(user_id):
      return db.query(...)

  # Manual invalidate:
  cache.invalidate("user:123")

  # Invalidate by prefix:
  cache.invalidate_prefix("user:")
"""

import threading
import time
import functools


class TTLCache:
    """In-memory cache with per-key TTL and background pruning."""

    def __init__(self, max_size=5000):
        self._store: dict[str, tuple[float, object]] = {}
        self._lock = threading.RLock()
        self._max_size = max_size
        self._hits = 0
        self._misses = 0

    def get(self, key: str):
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self._misses += 1
                return None
            expires, value = entry
            if time.time() > expires:
                del self._store[key]
                self._misses += 1
                return None
            self._hits += 1
            return value

    def set(self, key: str, value, ttl: int = 60):
        with self._lock:
            # Prune if over max
            if len(self._store) >= self._max_size:
                self._prune_locked()
            self._store[key] = (time.time() + ttl, value)

    def invalidate(self, key: str):
        with self._lock:
            self._store.pop(key, None)

    def invalidate_prefix(self, prefix: str):
        with self._lock:
            keys = [k for k in self._store if k.startswith(prefix)]
            for k in keys:
                del self._store[k]

    def clear(self):
        with self._lock:
            self._store.clear()

    def _prune_locked(self):
        """Remove expired entries. Must be called with lock held."""
        now = time.time()
        expired = [k for k, (exp, _) in self._store.items() if now > exp]
        for k in expired:
            del self._store[k]
        # If still over max after pruning expired, drop oldest entries
        if len(self._store) >= self._max_size:
            sorted_keys = sorted(self._store.keys(), key=lambda k: self._store[k][0])
            for k in sorted_keys[: len(self._store) // 4]:
                del self._store[k]

    @property
    def stats(self) -> dict:
        with self._lock:
            total = self._hits + self._misses
            return {
                "size": len(self._store),
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": round(self._hits / max(1, total) * 100, 1),
            }

    def __len__(self):
        return len(self._store)


# Global singleton
cache = TTLCache()


def cached(ttl: int = 60, key_prefix: str = ""):
    """Decorator: cache function results with TTL. Cache key = prefix + args + kwargs."""

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            # Build cache key
            parts = [key_prefix or fn.__name__]
            parts.extend(str(a) for a in args)
            parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))
            key = ":".join(parts)

            result = cache.get(key)
            if result is not None:
                return result
            result = fn(*args, **kwargs)
            if result is not None:
                cache.set(key, result, ttl=ttl)
            return result

        wrapper.invalidate = lambda *a, **kw: cache.invalidate(
            ":".join([key_prefix or fn.__name__] + [str(x) for x in a] + [f"{k}={v}" for k, v in sorted(kw.items())])
        )
        return wrapper

    return decorator
