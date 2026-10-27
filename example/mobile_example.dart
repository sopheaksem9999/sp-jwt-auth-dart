// Mobile setup with a pure-Dart store. Compiled by `dart analyze`.
//
// In a Flutter app, replace [InMemoryStorage] with the companion package
// `sp_jwt_auth_flutter` (not published yet; add it as a path dependency):
//
//   import 'package:sp_jwt_auth_flutter/sp_jwt_auth_flutter.dart';
//   final store = SecureStorageTokenStore();      // keychain / keystore
//   final listenable = SpAuthListenable(auth);    // GoRouter refreshListenable
import 'package:dio/dio.dart';
import 'package:sp_jwt_auth/sp_jwt_auth.dart';

/// Stub [KeyValueStorage]; a real app wraps a secure keychain here.
class InMemoryStorage implements KeyValueStorage {
  final Map<String, String> _data = {};

  @override
  Future<String?> read(String key) async => _data[key];

  @override
  Future<void> write(String key, String value) async => _data[key] = value;

  // Must not throw for a missing key.
  @override
  Future<void> delete(String key) async => _data.remove(key);
}

SpJwtAuth buildAuth() {
  return SpJwtAuth(
    baseUrl: Uri.parse('https://api.example.com/api/v1'),
    endpoints: const Endpoints(
      login: '/auth/login',
      refresh: '/auth/refresh',
      logout: '/auth/logout',
      whoami: '/auth/whoami',
      otpResend: '/auth/otp/resend',
      relativeToBase: true, // https://api.example.com/api/v1/auth/login
    ),
    otpOptions: OtpOptions(
      sendBody: (identifier, channel) => {
        'phone': identifier,
        if (channel != null) 'channel': channel,
      },
    ),
    store: KeyValueTokenStore(InMemoryStorage()),
    dio: Dio(),
  );
}

Future<void> main() async {
  final auth = buildAuth();
  await auth.restore();

  // Synchronous snapshot for routing decisions (no I/O, never refreshes).
  print('signed in: ${auth.isAuthenticated} user: ${auth.userId}');

  final removeListener = auth.addListener(() {
    print('session changed: ${auth.currentSession?.user}');
  });

  // Call from WidgetsBindingObserver.didChangeAppLifecycleState(resumed).
  auth.onResumed();

  // Pair with sp_laravel_api: ApiAuth(
  //   headers: auth.headers,
  //   handleUnauthorized: auth.handleUnauthorized,
  // ). Do NOT also call auth.attach(dio) on that same Dio.

  removeListener();
  auth.dispose();
}
