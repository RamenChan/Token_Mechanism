from app.tokens import refresh_store
from dataclasses import dataclass


class SimpleRedis:
	def __init__(self):
		self.store = {}

	def hset(self, key, *args, **kwargs):
		# support hset(key, mapping={...}) and hset(key, field, value)
		mapping = None
		if len(args) == 1 and isinstance(args[0], dict):
			mapping = args[0]
		elif len(args) == 2:
			field, val = args
			mapping = {field: val}
		elif "mapping" in kwargs:
			mapping = kwargs.pop("mapping")
		elif kwargs:
			mapping = kwargs

		if mapping is None:
			return

		self.store.setdefault(key, {})
		self.store[key] = dict(self.store.get(key, {}))
		self.store[key].update(mapping)

	def hgetall(self, key):
		return dict(self.store.get(key, {}))

	def expireat(self, key, when):
		# noop for tests
		return True

	def hget(self, key, field):
		return self.store.get(key, {}).get(field)

	def exists(self, key):
		return key in self.store

	def setex(self, key, ttl, val):
		self.store[key] = val

	def get(self, key):
		return self.store.get(key)


def test_mint_and_get_refresh():
	# patch the redis client
	simple = SimpleRedis()
	refresh_store.r = simple

	raw = refresh_store.mint_refresh("usr_alice", "sid_1", "dev1")
	assert isinstance(raw, str)

	rec = refresh_store.get_refresh(raw)
	assert rec is not None
	assert rec.user_id == "usr_alice"


def test_consume_and_reuse_detection():
	simple = SimpleRedis()
	refresh_store.r = simple

	raw = refresh_store.mint_refresh("usr_bob", "sid_2", "dev2")
	ok, reuse = refresh_store.consume_refresh_with_reuse_detection(raw)
	assert ok is True and reuse is False

	# second time should indicate reuse
	ok2, reuse2 = refresh_store.consume_refresh_with_reuse_detection(raw)
	assert ok2 is False and reuse2 is True


def test_revoke_session_flag():
	simple = SimpleRedis()
	refresh_store.r = simple

	refresh_store.revoke_session("sess_123")
	assert refresh_store.is_session_revoked("sess_123") is True
