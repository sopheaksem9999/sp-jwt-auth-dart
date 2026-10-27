# sp_jwt_auth

First-party JWT access and rotating refresh token authentication for Dart and Flutter.

## Features

- **Single-Flight Refresh:** Automatically deduplicates concurrent token rotations across asynchronous calls.
- **Proactive Expiration Renewal:** Seamlessly refreshes tokens ahead of time before expiration.
- **Cross-Platform & Pure Dart:** Zero Flutter SDK dependencies in core libraries; compatible with mobile, desktop, web, and Wasm.
- **Cross-Isolate & Cross-Tab Safety:** Synchronized refresh via `RefreshLock` (in-process, file-based for isolates, and Web Locks API for web).
- **Failure Classification:** Distinguishes definitive authorization failures from transient network or server errors.

## Installation

Add `sp_jwt_auth` to your `pubspec.yaml`:

```yaml
dependencies:
  sp_jwt_auth:
    git:
      url: https://github.com/sopheaksem9999/sp-jwt-auth-dart.git
      ref: v0.1.0-beta.1
```

## Quick Start

```dart
import 'package:sp_jwt_auth/sp_jwt_auth.dart';

final auth = SpJwtAuth(
  baseUrl: Uri.parse('https://api.example.com'),
  endpoints: Endpoints(
    login: '/auth/login',
    refresh: '/auth/refresh',
    logout: '/auth/logout',
    whoami: '/auth/whoami',
    parseSession: (data) => StoredSession.fromJson(data as Map<String, dynamic>),
  ),
  store: MemoryTokenStore(),
);

await auth.restore();
```

## Verification Status

- **Fake Backend & In-Process Tests:** Verified in CI.
- **Platform Matrix:** Tested on Dart 3.8.0 and latest stable.
