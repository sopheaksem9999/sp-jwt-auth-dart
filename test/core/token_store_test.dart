import 'package:sp_jwt_auth/src/token_store.dart';
import 'package:test/test.dart';

void main() {
  test('MemoryTokenStore read/write/clear roundtrip', () async {
    final store = MemoryTokenStore();
    expect(await store.read(), isNull);

    final session = StoredSession(
      accessToken: 'at_123',
      refreshToken: 'rt_456',
      expiresAt: DateTime.utc(2027, 1, 1),
      user: {'id': 1, 'name': 'Alice'},
    );
    await store.write(session);
    final readBack = await store.read();
    expect(readBack?.accessToken, equals('at_123'));
    expect(readBack?.refreshToken, equals('rt_456'));
    expect(readBack?.user?['name'], equals('Alice'));

    await store.clear();
    expect(await store.read(), isNull);
  });

  test('StoredSession json serialization and deserialization', () {
    final session = StoredSession(
      accessToken: 'at_123',
      refreshToken: 'rt_456',
      expiresAt: DateTime.utc(2027, 1, 1),
      user: {'id': 1},
    );
    final json = session.toJson();
    final restored = StoredSession.fromJson(json);
    expect(restored.accessToken, equals('at_123'));
    expect(restored.refreshToken, equals('rt_456'));
    expect(restored.expiresAt, equals(DateTime.utc(2027, 1, 1)));
    expect(restored.user?['id'], equals(1));
  });
}
