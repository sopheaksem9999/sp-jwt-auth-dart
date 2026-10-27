import 'dart:async';
import 'package:dio/dio.dart';
import 'package:sp_jwt_auth/sp_jwt_auth.dart';

/// Kill switch feature flag for gradual rollout in client applications.
const bool useNewAuthClient = bool.fromEnvironment(
  'USE_SP_JWT_AUTH',
  defaultValue: true,
);

/// Example implementation of [TokenStore] wrapping secure key-value storage.
class InMemoryDemoTokenStore implements TokenStore {
  final Map<String, String> _storage = {};

  @override
  Future<StoredSession?> read() async {
    final raw = _storage['user_session'];
    if (raw == null) return null;
    try {
      final json = StoredSession.fromJson(
        Map<String, dynamic>.from(
          // In real apps: jsonDecode(raw)
          {'access_token': raw},
        ),
      );
      return json;
    } catch (_) {
      return null;
    }
  }

  @override
  Future<void> write(StoredSession session) async {
    _storage['user_session'] = session.accessToken;
    _storage['access_token'] = session.accessToken;
    if (session.refreshToken != null) {
      _storage['refresh_token'] = session.refreshToken!;
    }
  }

  @override
  Future<void> clear() async {
    _storage.remove('user_session');
    _storage.remove('access_token');
    _storage.remove('refresh_token');
  }
}

Future<void> main() async {
  // 1. Initialize secure storage seam
  final tokenStore = InMemoryDemoTokenStore();

  // 2. Configure auth endpoints
  final endpoints = Endpoints(
    login: '/api/v1/auth/login',
    refresh: '/api/v1/auth/refresh',
    logout: '/api/v1/auth/logout',
    whoami: '/api/v1/auth/whoami',
    parseSession: (data) {
      final map =
          (data as Map<String, dynamic>)['data'] as Map<String, dynamic>;
      return StoredSession(
        accessToken: map['access_token'] as String,
        refreshToken: map['refresh_token'] as String?,
        expiresAt: DateTime.fromMillisecondsSinceEpoch(
          (map['expires_at'] as int) * 1000,
          isUtc: true,
        ),
        user: map['user'] as Map<String, dynamic>?,
      );
    },
  );

  // 3. Create SpJwtAuth client
  final auth = SpJwtAuth(
    baseUrl: Uri.parse('https://api.example.com'),
    endpoints: endpoints,
    store: tokenStore,
    dio: Dio(),
  );

  // 4. Restore existing session on app startup
  await auth.restore();

  // 5. Listen to auth state changes (e.g. for GoRouter redirect)
  final sub = auth.changes.listen((state) {
    switch (state) {
      case Authenticated(:final user):
        print('User signed in: ${user['email']}');
      case Anonymous():
        print('User signed out or session ended');
      case Restoring():
        print('Restoring session...');
    }
  });

  print('Current Auth State: ${auth.state.runtimeType}');

  await sub.cancel();
  auth.dispose();
}
