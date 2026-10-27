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
}
