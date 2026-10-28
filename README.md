# sp_jwt_auth

Typed Dart & Flutter client service for the [`sopheak/sp-jwt-auth`](https://packagist.org/packages/sopheak/sp-jwt-auth) Laravel backend package.

> [!IMPORTANT]
> **Client Service Compatibility Notice:**  
> `sp_jwt_auth` is a client-side library and **works only with** backends running [`sopheak/sp-jwt-auth`](https://packagist.org/packages/sopheak/sp-jwt-auth). It handles token storage, proactive rotation, cross-tab and cross-isolate synchronization, and session lifecycles specifically tailored to the package's protocol.

## Features

- **Single-Flight Refresh Engine:** Deduplicates concurrent token refreshes into a single network flight.
- **Proactive Expiration Renewal:** Automatically refreshes tokens within the `refreshAhead` window before token expiry.
- **Pure Dart & Cross-Platform:** Zero Flutter SDK dependencies in core libraries; compatible with mobile (iOS, Android), desktop (macOS, Windows, Linux), web, and Wasm.
- **Cross-Isolate & Cross-Tab Safety:** Synchronized token rotation via `RefreshLock` (in-process, POSIX advisory file locking for background isolates, and browser Web Locks API for web).
- **Tab Synchronization:** `TabSync` communicates token refreshes and logouts across multiple browser tabs via `BroadcastChannel`.
- **HttpOnly Cookie Support:** Native and web support for cookie-based transport with automated CSRF protection (`Csrf` config).
- **Auth Feature Modules:** Typed modules for OTP login/verification (`OtpModule`), multi-factor authentication (`MfaModule`), device session management (`SessionsModule`), and profile/password updates (`AccountModule`).

## Installation

Add `sp_jwt_auth` to your `pubspec.yaml`:

```yaml
dependencies:
  sp_jwt_auth: ^0.2.0
```

Or install from git:

```yaml
dependencies:
  sp_jwt_auth:
    git:
      url: https://github.com/sopheaksem9999/sp-jwt-auth-dart.git
      ref: v0.2.0
```

## Quick Start

```dart
import 'package:dio/dio.dart';
import 'package:sp_jwt_auth/sp_jwt_auth.dart';

final auth = SpJwtAuth(
  baseUrl: Uri.parse('https://api.example.com'),
  endpoints: Endpoints(
    login: '/api/v1/auth/login',
    refresh: '/api/v1/auth/refresh',
    logout: '/api/v1/auth/logout',
    whoami: '/api/v1/auth/whoami',
    parseSession: (data) {
      final map = (data as Map<String, dynamic>)['data'] as Map<String, dynamic>;
      return StoredSession.fromJson(map);
    },
  ),
  store: MemoryTokenStore(), // In-memory only: the session is lost on restart.
  // For persistence use KeyValueTokenStore, or on Flutter the companion
  // package sp_jwt_auth_flutter (see "Flutter mobile" below).
  dio: Dio(),
);

// Restore session on app launch
await auth.restore();
```

## Request logging

Off by default. Set a logger and the global switch to get one line per HTTP
attempt the package makes (login, refresh, logout, whoami, OTP, MFA, sessions,
account):

```dart
final auth = SpJwtAuth(
  // ...
  logger: AuthLogger(sink: (e) => debugPrint('$e')),
  logRequests: true,
);
// POST /auth/login -> 200 85ms rid=abc attempt=1
```

Bodies, headers and query strings are never logged: `AuthLogEntry` has no field
for them. The sink is yours (`debugPrint`, `print`, your own logger); errors it
throws are swallowed and never affect the request.

What to know before you ship it:

- Paths are logged verbatim: a session id in a path (`/auth/sessions/<id>`)
  appears as is in `path`.
- The sink runs inline, on the request path, so keep it quick and hand slow
  work off without awaiting it.
- Only calls made by this package are logged. App requests that
  `SpJwtAuthInterceptor` replays after a 401 are not; the refresh call it
  triggers is.
- `attempt` counts the HTTP attempts of one call: a refresh retried after a
  CSRF failure (cookie transport) is logged as attempt 1, then attempt 2.
- `code` classifies the HTTP response, not the error the caller gets: every
  `success: false` envelope is logged as `unauthenticated`, so a refresh
  answered with `error_code` 10002 shows `unauthenticated` while the caller
  gets `refreshReuseDetected`.
- A method other than GET, POST, PUT or DELETE passed to `SpJwtAuth.send`
  throws `ArgumentError`; nothing is sent or logged.

## Flutter mobile

Persistent storage on a device needs a platform keychain. The core package stays pure Dart, so it ships the storage seam and the Flutter pieces live in a companion package.

- **`KeyValueTokenStore`** (this package): a `TokenStore` over any `KeyValueStorage` (`read`/`write`/`delete` of strings). Key names are overridable through `StorageKeys` (defaults `sp_access_token`, `sp_refresh_token`, `sp_access_token_expires_at`, `sp_user`). `expiresAt` is read as ISO-8601 or epoch seconds and written as ISO-8601 UTC.
- **`KeyValueStorage.delete` must not throw for a missing key.** `write` deletes the access token first and writes it last (the access token is the presence marker, so a crash mid-write reads as logged out, never as a mixed session), and `clear` deletes every key.
- **`SecureStorageTokenStore` and `SpAuthListenable` will live in a companion package, `sp_jwt_auth_flutter`**, which is **not published yet**. Until it is, plug a platform keychain into `KeyValueTokenStore` yourself with a small `KeyValueStorage` adapter over `flutter_secure_storage` (add it to your app's `pubspec.yaml`):

```dart
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:sp_jwt_auth/sp_jwt_auth.dart';

class FlutterSecureKeyValue implements KeyValueStorage {
  FlutterSecureKeyValue([this._s = const FlutterSecureStorage()]);
  final FlutterSecureStorage _s;

  @override
  Future<String?> read(String key) => _s.read(key: key);
  @override
  Future<void> write(String key, String value) =>
      _s.write(key: key, value: value);
  // FlutterSecureStorage.delete on a missing key is a no-op, as required.
  @override
  Future<void> delete(String key) => _s.delete(key: key);
}

final store = KeyValueTokenStore(FlutterSecureKeyValue());
```

A compile-checked, Flutter-free version of this setup is in [`example/mobile_example.dart`](example/mobile_example.dart).

```dart
final auth = SpJwtAuth(
  baseUrl: Uri.parse('https://api.example.com/api/v1'),
  endpoints: const Endpoints(
    relativeToBase: true,
    otpSend: '/auth/otp/send', // old 0.1.0 paths; defaults are /otp/request, /otp/verify, /otp/resend
    otpVerify: '/auth/otp/verify',
    otpResend: '/auth/otp/resend',
  ),
  otpOptions: OtpOptions(
    sendBody: (identifier, channel) => {'phone': identifier},
  ),
  // sp_jwt_auth_flutter: SecureStorageTokenStore()
  store: KeyValueTokenStore(myKeyValueStorage),
);

await auth.restore();                 // on launch
auth.onResumed();                     // when the app returns to the foreground

// Synchronous reads for routers and UI (no I/O, never refreshes):
auth.isAuthenticated; auth.userId; auth.currentSession; auth.accessTokenSync;
final remove = auth.addListener(() { /* session changed */ });
```

`addListener` fires after restore, login, refresh, logout and cross-tab sync, with the snapshot already updated; an exception thrown by one listener does not stop the others. `sp_jwt_auth_flutter` wraps this as a `ChangeNotifier` (`SpAuthListenable`) for `GoRouter(refreshListenable: ...)`. A refresh response without a `user` keeps the previously stored user, so `currentSession.user` and `restore()` still return it after a rotation.

### OTP login

By default OTP follows the backend routes: `sendOtp(identifier:, channel:, purpose: 'login')` posts `{destination, channel, purpose}` to `/otp/request` and keeps the `otp_id` from the 202 response; `verifyOtp` posts `{otp_id, code, destination, channel}` to `/otp/verify`; `resendOtp` posts `{otp_id, destination, channel}` to `/otp/resend`. The backend requires `channel` (`email` or `sms`), so `sendOtp` defaults it to `email` and the captured channel is reused for verify and resend. `verifyOtp` and `resendOtp` throw `StateError` when no `otp_id` was captured (for example after an app restart) unless a custom `OtpOptions.verifyBody` / `sendBody` is set. `Endpoints` paths and `OtpOptions` builders override all of this (for example the paths of earlier releases, `/auth/otp/send` and `/auth/otp/verify`).

### Endpoint paths: absolute vs relative

`Endpoints.relativeToBase` controls how every endpoint path (login, refresh, logout, whoami, OTP, MFA, sessions, account) is joined to `baseUrl`:

| `relativeToBase` | Path treatment | `baseUrl` `https://h/api/v1` + `/auth/login` |
| --- | --- | --- |
| `false` (default) | Absolute: a path starting with `/` replaces the `baseUrl` path | `https://h/auth/login` |
| `true` | Relative: the path is appended beneath the `baseUrl` path | `https://h/api/v1/auth/login` |

With `true`, a `baseUrl` query string is dropped (RFC 3986 reference resolution). Both modes are pinned in [`test/core/url_test.dart`](test/core/url_test.dart).

### Response parsing and failures

`Endpoints.parseSession` is optional. The default, `StoredSession.fromEnvelope`, accepts `{success, data: {...}}` envelopes and flat bodies and derives `expiresAt` from `expires_in`; pass your own function to override it. An HTTP 200 with `{"success": false}` throws `SpAuthError` (with `message`, `errorCode`, `requestId`) instead of storing an empty session ([`test/core/envelope_test.dart`](test/core/envelope_test.dart)).

### Pairing with `sp_laravel_api`

```dart
final api = ApiAuth(
  headers: auth.headers,
  handleUnauthorized: auth.handleUnauthorized,
);
```

> [!WARNING]
> Do not also call `attach(dio)` on the same `Dio`. `attach(dio)` installs a second refreshing interceptor, so a 401 would be handled twice. Use either `ApiAuth` with `headers`/`handleUnauthorized`, or `attach(dio)`, never both.

### Security properties and their tests

- Crash mid-write never yields a half-session: [`test/core/key_value_token_store_test.dart`](test/core/key_value_token_store_test.dart).
- Concurrent refreshes are deduplicated into a single network flight: [`test/core/refresh_engine_test.dart`](test/core/refresh_engine_test.dart).
- A failed login leaves an existing session intact: [`test/core/envelope_test.dart`](test/core/envelope_test.dart).
- `accessTokenSync` never starts a request, and a throwing listener cannot block others: [`test/core/session_snapshot_test.dart`](test/core/session_snapshot_test.dart).
- Cookie transport sends CSRF protection: [`test/web/cookie_transport_test.dart`](test/web/cookie_transport_test.dart).

## Flutter & Riverpod Integration

```dart
// State notifier or Riverpod provider
final authStateProvider = StreamProvider<AuthState>((ref) {
  return auth.changes;
});

// GoRouter redirect guard
String? authRedirectGuard(BuildContext context, GoRouterState state) {
  final authState = auth.state;
  final loggingIn = state.matchedLocation == '/login';

  if (authState is Anonymous && !loggingIn) {
    return '/login';
  }
  if (authState is Authenticated && loggingIn) {
    return '/dashboard';
  }
  return null;
}
```

## App Lifecycle Integration

Call `onResumed()` when the application returns to the foreground to proactively refresh near-expiry tokens:

```dart
// In your AppLifecycleListener or WidgetsBindingObserver:
@override
void didChangeAppLifecycleState(AppLifecycleState state) {
  if (state == AppLifecycleState.resumed) {
    auth.onResumed();
  }
}
```

## Verification & Status

- **Automated Tests:** unit, concurrency, web locks, storage compatibility and README checks (`dart test`).
- **Platform Matrix:** Verified on Dart SDK `>=3.8.0 <4.0.0` and latest stable.
- **Web & Wasm:** Verified clean JavaScript compilation and browser Web Locks integration.
- **Public-Repo Hygiene:** Zero forbidden internal names; automated secret scanning with Gitleaks.
