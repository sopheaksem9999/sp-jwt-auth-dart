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
  sp_jwt_auth: ^0.1.0-beta.2
```

Or install from git:

```yaml
dependencies:
  sp_jwt_auth:
    git:
      url: https://github.com/sopheaksem9999/sp-jwt-auth-dart.git
      ref: v0.1.0-beta.2
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
  store: MemoryTokenStore(), // Use SecureStorageTokenStore in production
  dio: Dio(),
);

// Restore session on app launch
await auth.restore();
```

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

- **Automated Tests:** 52 tests passing (unit, concurrency, web locks, storage compatibility).
- **Platform Matrix:** Verified on Dart SDK `>=3.8.0 <4.0.0` and latest stable.
- **Web & Wasm:** Verified clean JavaScript compilation and browser Web Locks integration.
- **Public-Repo Hygiene:** Zero forbidden internal names; automated secret scanning with Gitleaks.
