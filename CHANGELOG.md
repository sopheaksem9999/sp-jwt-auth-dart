# Changelog

## 0.1.0 (2026-10-27)

- First stable release of `sp_jwt_auth` for Dart and Flutter.
- Added strongly-typed `SessionEndReason` enum (`manualLogout`, `crossTabLogout`, `tokenExpired`, `refreshRejected`, `storageCleared`).
- Added synchronous `isHydrated` getter and explicit `ready()` method on `SpAuth`.
- Enhanced session ended events with typed reason metadata.

## 0.1.0-beta.2 (2026-10-27)

- Verified automated GitHub Actions OIDC publishing pipeline to pub.dev.
- Enhanced CI hygiene tooling with default fallback checks.

## 0.1.0-beta.1 (2026-10-27)

- Initial beta release of `sp_jwt_auth` for Dart and Flutter.
- Single-flight rotating refresh token synchronization.
- Sealed `AuthState` and `AuthEvent` streams.
- Pluggable `TokenStore` and `RefreshLock` architecture.
- Web Locks and httpOnly refresh cookie transport support.
