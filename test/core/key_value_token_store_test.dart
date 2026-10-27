import 'package:sp_jwt_auth/sp_jwt_auth.dart';
import 'package:test/test.dart';

class _MemStorage implements KeyValueStorage {
  final Map<String, String> data = {};
  @override
  Future<String?> read(String key) async => data[key];
  @override
  Future<void> write(String key, String value) async => data[key] = value;
  @override
  Future<void> delete(String key) async => data.remove(key);
}

class _FailingStorage extends _MemStorage {
  final ops = <String>[];
  int? failAt;
  void _op(String o) {
    if (failAt != null && ops.length == failAt) throw StateError('crash');
    ops.add(o);
  }

  @override
  Future<void> write(String key, String value) async {
    _op('w:$key');
    await super.write(key, value);
  }

  @override
  Future<void> delete(String key) async {
    _op('d:$key');
    await super.delete(key);
  }
}

class _DeleteThrows extends _MemStorage {
  final String badKey;
  _DeleteThrows(this.badKey);
  @override
  Future<void> delete(String key) async {
    if (key == badKey) throw StateError('boom');
    await super.delete(key);
  }
}

void main() {
  late _MemStorage storage;
  late KeyValueTokenStore store;

  setUp(() {
    storage = _MemStorage();
    store = KeyValueTokenStore(storage);
  });

  final exp = DateTime.utc(2026, 1, 1, 12);

  test(
    'write then read returns equal StoredSession incl. expiresAt and user',
    () async {
      await store.write(
        StoredSession(
          accessToken: 'a',
          refreshToken: 'r',
          expiresAt: exp,
          user: {'id': 1, 'name': 'Acme'},
        ),
      );
      expect(storage.data['sp_access_token'], 'a');
      expect(storage.data['sp_refresh_token'], 'r');
      expect(storage.data['sp_access_token_expires_at'], exp.toIso8601String());
      final s = (await store.read())!;
      expect(s.accessToken, 'a');
      expect(s.refreshToken, 'r');
      expect(s.expiresAt, exp);
      expect(s.expiresAt!.isUtc, isTrue);
      expect(s.user, {'id': 1, 'name': 'Acme'});
    },
  );

  test('non-UTC expiresAt is written as UTC ISO-8601', () async {
    await store.write(
      StoredSession(accessToken: 'a', expiresAt: exp.toLocal()),
    );
    expect(storage.data['sp_access_token_expires_at'], exp.toIso8601String());
  });

  test('custom key names read back, ISO and epoch-seconds expiry', () async {
    final custom = KeyValueTokenStore(
      storage,
      keys: const StorageKeys(
        accessToken: 'my_access',
        refreshToken: 'my_refresh',
        expiresAt: 'my_exp',
        user: 'my_user',
      ),
    );
    storage.data.addAll({
      'my_access': 'a',
      'my_refresh': 'r',
      'my_exp': exp.toIso8601String(),
      'my_user': '{"id":2}',
    });
    var s = (await custom.read())!;
    expect(s.expiresAt, exp);
    expect(s.user, {'id': 2});
    storage.data['my_exp'] = '1767225600';
    s = (await custom.read())!;
    expect(
      s.expiresAt,
      DateTime.fromMillisecondsSinceEpoch(1767225600000, isUtc: true),
    );
    await custom.write(StoredSession(accessToken: 'b'));
    expect(storage.data['my_access'], 'b');
    expect(storage.data.containsKey('sp_access_token'), isFalse);
  });

  test('clear removes every key written', () async {
    await store.write(
      StoredSession(
        accessToken: 'a',
        refreshToken: 'r',
        expiresAt: exp,
        user: {'id': 1},
      ),
    );
    await store.clear();
    expect(storage.data, isEmpty);
  });

  test('clear attempts every delete and rethrows the first error', () async {
    final failing = _DeleteThrows('sp_refresh_token');
    final s = KeyValueTokenStore(failing);
    failing.data.addAll({
      'sp_access_token': 'a',
      'sp_refresh_token': 'r',
      'sp_access_token_expires_at': 'e',
      'sp_user': '{}',
    });
    await expectLater(s.clear(), throwsA(isA<StateError>()));
    expect(failing.data.keys, ['sp_refresh_token']);
  });

  test('write with null optional fields deletes stale keys', () async {
    await store.write(
      StoredSession(
        accessToken: 'a',
        refreshToken: 'r',
        expiresAt: exp,
        user: {'id': 1},
      ),
    );
    await store.write(const StoredSession(accessToken: 'b'));
    expect(storage.data, {'sp_access_token': 'b'});
  });

  test('read with only refresh token present returns null', () async {
    storage.data['sp_refresh_token'] = 'r';
    expect(await store.read(), isNull);
  });

  test('corrupt user JSON throws SpAuthError(storageError)', () async {
    storage.data['sp_access_token'] = 'a';
    storage.data['sp_user'] = '{not json';
    expect(
      store.read(),
      throwsA(
        isA<SpAuthError>().having(
          (e) => e.code,
          'code',
          SpAuthErrorCode.storageError,
        ),
      ),
    );
    storage.data['sp_user'] = '[1,2]';
    expect(
      store.read(),
      throwsA(
        isA<SpAuthError>().having(
          (e) => e.code,
          'code',
          SpAuthErrorCode.storageError,
        ),
      ),
    );
  });

  test('unparseable expiry is treated as absent', () async {
    storage.data['sp_access_token'] = 'a';
    storage.data['sp_access_token_expires_at'] = 'garbage';
    expect((await store.read())!.expiresAt, isNull);
  });

  test('SpJwtAuth restores after restart with same storage', () async {
    SpJwtAuth make() => SpJwtAuth(
      baseUrl: Uri.parse('https://api.example.com'),
      endpoints: const Endpoints(
        login: '/auth/login',
        refresh: '/auth/refresh',
        logout: '/auth/logout',
        whoami: '/auth/whoami',
      ),
      store: KeyValueTokenStore(storage),
    );
    await KeyValueTokenStore(
      storage,
    ).write(StoredSession(accessToken: 'a', user: {'id': 7}));
    final auth = make();
    await auth.restore();
    expect(auth.isAuthenticated, isTrue);
    expect(auth.currentSession!.accessToken, 'a');
  });

  test('write puts the access token last', () async {
    final fs = _FailingStorage();
    await KeyValueTokenStore(fs).write(
      StoredSession(
        accessToken: 'a',
        refreshToken: 'r',
        expiresAt: exp,
        user: {'id': 1},
      ),
    );
    expect(fs.ops.last, 'w:sp_access_token');
  });

  test('crash midway through a rewrite never yields a half-session', () async {
    const old = StoredSession(
      accessToken: 'old',
      refreshToken: 'oldr',
      user: {'id': 1},
    );
    final next = StoredSession(accessToken: 'new', expiresAt: exp);
    for (var n = 0; n < 6; n++) {
      final fs = _FailingStorage();
      final st = KeyValueTokenStore(fs);
      await st.write(old);
      fs.ops.clear();
      fs.failAt = n;
      try {
        await st.write(next);
      } catch (_) {}
      fs.failAt = null;
      final s = await st.read();
      if (s != null) {
        final complete =
            (s.accessToken == 'new' &&
                s.refreshToken == null &&
                s.user == null &&
                s.expiresAt == exp) ||
            (s.accessToken == 'old' &&
                s.refreshToken == 'oldr' &&
                s.user != null &&
                s.expiresAt == null);
        expect(complete, isTrue, reason: 'crash at op $n gave $s');
      }
    }
  });
}
