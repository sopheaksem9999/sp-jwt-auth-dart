import 'package:sp_jwt_auth/sp_jwt_auth.dart';
import 'package:test/test.dart';
import '../example/main.dart';

void main() {
  test('example InMemoryDemoTokenStore and workflow execute cleanly', () async {
    final store = InMemoryDemoTokenStore();
    expect(await store.read(), isNull);

    await store.write(const StoredSession(accessToken: 'sample_token'));
    final session = await store.read();
    expect(session?.accessToken, equals('sample_token'));

    await store.clear();
    expect(await store.read(), isNull);
  });
}
