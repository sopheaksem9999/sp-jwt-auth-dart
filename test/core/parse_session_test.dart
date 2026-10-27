import 'package:sp_jwt_auth/sp_jwt_auth.dart';
import 'package:test/test.dart';

void main() {
  DateTime now() => DateTime.utc(2026, 1, 1);
  StoredSession parse(dynamic body) =>
      StoredSession.fromEnvelope(body, now: now);

  test('envelope with expires_in 900', () {
    final s = parse({
      'success': true,
      'data': {'access_token': 'a', 'refresh_token': 'r', 'expires_in': 900},
    });
    expect(s.accessToken, 'a');
    expect(s.refreshToken, 'r');
    expect(s.expiresAt, DateTime.utc(2026, 1, 1, 0, 15));
  });

  test('flat body still parses', () {
    final s = parse({
      'access_token': 'a',
      'refresh_token': 'r',
      'expires_at': '2026-02-01T00:00:00.000Z',
    });
    expect(s.accessToken, 'a');
    expect(s.expiresAt, DateTime.utc(2026, 2, 1));
  });

  test('neither expires_in nor expires_at gives null expiresAt', () {
    expect(parse({'access_token': 'a'}).expiresAt, isNull);
  });

  test('camelCase keys', () {
    final s = parse({
      'data': {'accessToken': 'a', 'refreshToken': 'r', 'expiresIn': 60},
    });
    expect(s.accessToken, 'a');
    expect(s.refreshToken, 'r');
    expect(s.expiresAt, DateTime.utc(2026, 1, 1, 0, 1));
  });

  test('expires_at wins over expires_in', () {
    final s = parse({
      'access_token': 'a',
      'expires_in': 900,
      'expires_at': '2026-02-01T00:00:00.000Z',
    });
    expect(s.expiresAt, DateTime.utc(2026, 2, 1));
  });

  test('expires_in numeric string is parsed', () {
    expect(
      parse({'access_token': 'a', 'expires_in': '900'}).expiresAt,
      DateTime.utc(2026, 1, 1, 0, 15),
    );
  });

  test('negative or zero expires_in is treated as absent', () {
    expect(parse({'access_token': 'a', 'expires_in': -5}).expiresAt, isNull);
    expect(parse({'access_token': 'a', 'expires_in': 0}).expiresAt, isNull);
  });

  test('data null or list does not throw a cast error', () {
    expect(() => parse({'data': null}), throwsA(isA<SpAuthError>()));
    expect(() => parse({'data': <dynamic>[]}), throwsA(isA<SpAuthError>()));
    expect(parse({'data': <dynamic>[], 'access_token': 'a'}).accessToken, 'a');
  });

  test('missing or empty access_token throws SpAuthError', () {
    expect(() => parse({'refresh_token': 'r'}), throwsA(isA<SpAuthError>()));
    expect(() => parse({'access_token': ''}), throwsA(isA<SpAuthError>()));
    expect(() => parse('nope'), throwsA(isA<SpAuthError>()));
  });

  test('custom parseSession override is used', () {
    var called = false;
    final endpoints = Endpoints(
      parseSession: (d) {
        called = true;
        return const StoredSession(accessToken: 'custom');
      },
    );
    expect(endpoints.parseSession(<String, dynamic>{}).accessToken, 'custom');
    expect(called, isTrue);
  });

  test('default Endpoints is const and uses envelope parser', () {
    const endpoints = Endpoints();
    final s = endpoints.parseSession({
      'data': {'access_token': 'a'},
    });
    expect(s.accessToken, 'a');
  });
}
