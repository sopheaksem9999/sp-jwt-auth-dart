import 'dart:async';
import 'package:sp_jwt_auth/sp_jwt_auth.dart';
import 'package:test/test.dart';

void main() {
  group('Legacy Storage Snapshot & Compatibility Tests', () {
    test('parses snake_case legacy storage snapshot (App A format)', () {
      final legacySnapshot = <String, dynamic>{
        'access_token': 'legacy_jwt_access_token_123',
        'refresh_token': 'legacy_refresh_token_456',
        'expires_at': '2026-12-31T23:59:59.000Z',
        'user': {'id': 101, 'email': 'driver@example.com', 'role': 'driver'},
      };

      final session = StoredSession.fromJson(legacySnapshot);

      expect(session.accessToken, equals('legacy_jwt_access_token_123'));
      expect(session.refreshToken, equals('legacy_refresh_token_456'));
      expect(
        session.expiresAt,
        equals(DateTime.parse('2026-12-31T23:59:59.000Z')),
      );
      expect(session.user?['role'], equals('driver'));

      // Verify round-trip serialization produces standard keys readable by legacy clients
      final json = session.toJson();
      expect(json['access_token'], equals('legacy_jwt_access_token_123'));
      expect(json['refresh_token'], equals('legacy_refresh_token_456'));
    });

    test(
      'parses epoch timestamp and camelCase legacy storage snapshot (App B format)',
      () {
        final legacySnapshot = <String, dynamic>{
          'accessToken': 'legacy_camel_at_789',
          'refreshToken': 'legacy_camel_rt_012',
          'expires_at': 1767225599, // Unix epoch seconds
          'user': {'id': 202, 'name': 'Dispatcher Alice'},
        };

        final session = StoredSession.fromJson(legacySnapshot);

        expect(session.accessToken, equals('legacy_camel_at_789'));
        expect(session.refreshToken, equals('legacy_camel_rt_012'));
        expect(session.expiresAt?.isUtc, isTrue);
        expect(session.user?['name'], equals('Dispatcher Alice'));
      },
    );

    test(
      'keychain locked exception preserves stored tokens and does not clear session',
      () async {
        final throwingStore = _LockedKeychainTokenStore();

        final auth = SpJwtAuth(
          baseUrl: Uri.parse('https://api.example.com'),
          endpoints: Endpoints(
            login: '/auth/login',
            refresh: '/auth/refresh',
            logout: '/auth/logout',
            whoami: '/auth/whoami',
            parseSession: (d) => throw UnimplementedError(),
          ),
          store: throwingStore,
        );

        // Attempting restore when storage is locked throws or fails gracefully
        // but MUST NOT invoke store.clear() or wipe the underlying credentials
        try {
          await auth.restore();
        } catch (_) {}

        expect(throwingStore.clearCalled, isFalse);
        expect(throwingStore.underlyingSessionPreserved, isTrue);

        auth.dispose();
      },
    );
  });
}

class _LockedKeychainTokenStore implements TokenStore {
  bool clearCalled = false;
  bool underlyingSessionPreserved = true;

  @override
  Future<StoredSession?> read() async {
    // Simulates iOS ErrSecItemNotFound or keychain locked when device is locked
    throw StateError(
      'OSStatus -25308: Keychain item cannot be accessed while device is locked.',
    );
  }

  @override
  Future<void> write(StoredSession session) async {}

  @override
  Future<void> clear() async {
    clearCalled = true;
    underlyingSessionPreserved = false;
  }
}
