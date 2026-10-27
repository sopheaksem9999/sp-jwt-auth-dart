# Changelog

## Unreleased

- Added: `Endpoints.relativeToBase` (default `false`, behavior unchanged) joins endpoint paths beneath the `baseUrl` path, e.g. `https://h/api/v1` + `/auth/login`; new public `SpJwtAuth.endpointUri(path)` is used by the core and all modules (J2).
- Added: `Endpoints.parseSession` is now optional; the default parses `{success, data: {...}}` envelopes and flat bodies via `StoredSession.fromEnvelope`, deriving `expiresAt` from `expires_in` (J3).
- Fixed: `login`, `otp.verifyOtp` and the refresh path now throw `SpAuthError` (with `message`, `errorCode`, `requestId`) when the server returns HTTP 200 with `success: false`, instead of storing an empty session (J6).
- Added: configurable OTP via `Endpoints.otpSend`/`otpVerify`/`otpResend` and `OtpOptions` (`sendBody`, `verifyBody`, `challengeIdFrom`); new `OtpModule.resendOtp`; `SpJwtAuth.otp` is now one cached instance so a captured challenge id survives to verify (J4).
- Added: synchronous `SpJwtAuth.currentSession`, `isAuthenticated`, `userId`, `accessTokenSync` (no I/O, never refreshes) and `addListener(listener)` (returns a remover), notified after restore, login, refresh, logout and cross-tab sync with the snapshot already updated; listener exceptions are isolated (J5).

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
