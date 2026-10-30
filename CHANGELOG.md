# Changelog

## Unreleased

- Fix: a refresh answered `200 { success: false }` with a numeric-string `error_code` (`"10010"`, `"10002"`) now ends the session like the int does (`SessionEnded` with `refreshRejected`, `SpAuthError` `refreshReuseDetected` with the parsed `errorCode`). Only an int `error_code` was recognised on that path; the non-2xx path already parsed strings. Same behaviour as `@sokpheak/sp-jwt-auth`.

## 0.2.0 (2026-10-28)

- BREAKING: OTP defaults now follow the backend routes. `Endpoints.otpSend`/`otpVerify`/`otpResend` default to `/otp/request`, `/otp/verify` and `/otp/resend` (were `/auth/otp/send`, `/auth/otp/verify` and null). `sendOtp` posts `{destination, channel, purpose}` (`channel` now defaults to `email`, the backend requires it; new `purpose` parameter, default `login`), reads `otp_id` from the 202 response (top level or under `data`) and `verifyOtp` posts `{otp_id, code, destination, channel}`; `resendOtp` posts `{otp_id, destination, channel}`; `resendOtp` and `verifyOtp` throw `StateError` if no challenge id was captured (unless custom `OtpOptions` builders are set); a new send attempt clears the previous id and channel. `OtpOptions` builders still override the defaults. To keep the old behavior use `Endpoints(otpSend: '/auth/otp/send', otpVerify: '/auth/otp/verify')` with `OtpOptions` builders returning `{identifier, channel}` / `{identifier, code}`.
- Added: optional request logging (D2). `SpJwtAuth(logger: AuthLogger(sink: ...), logRequests: true)` delivers one `AuthLogEntry` (method, path without query, status, duration, request id, attempt, code, errorCode) per HTTP attempt of login, refresh, logout, whoami, OTP, MFA, sessions and account calls. Off by default; bodies, headers and query strings are never logged; a throwing sink is swallowed. All package HTTP calls now go through one internal helper `SpJwtAuth.send`, which throws `ArgumentError` for a method other than GET, POST, PUT or DELETE (it used to send an unknown method as a POST). The request id follows the same rule as `sp_laravel_api`: only a string is used (header `X-Request-Id`, else `meta.request_id`), control characters and U+2028/U+2029 are stripped, and it is cut to 128 code points (never inside a surrogate pair) and trimmed. The logged `path` is cleaned the same way and cut to 512 code points, as in sp-jwt-auth-js (`/` when empty).
- Fixed: a token refresh whose response carries no `user` (the documented shape) no longer drops the stored user; the previous user is carried into the stored session, the `Refreshed` event, `state` and the tab broadcast, so `currentSession.user` and `restore()` keep it. A `user` in the response still replaces the old one (R2).
- Added: `Endpoints.relativeToBase` (default `false`, behavior unchanged) joins endpoint paths beneath the `baseUrl` path, e.g. `https://h/api/v1` + `/auth/login`; new public `SpJwtAuth.endpointUri(path)` is used by the core and all modules (J2).
- Added: `Endpoints.parseSession` is now optional; the default parses `{success, data: {...}}` envelopes and flat bodies via `StoredSession.fromEnvelope`, deriving `expiresAt` from `expires_in` (J3).
- Fixed: `login`, `otp.verifyOtp` and the refresh path now throw `SpAuthError` (with `message`, `errorCode`, `requestId`) when the server returns HTTP 200 with `success: false`, instead of storing an empty session (J6).
- Added: configurable OTP via `Endpoints.otpSend`/`otpVerify`/`otpResend` and `OtpOptions` (`sendBody`, `verifyBody`, `challengeIdFrom`); new `OtpModule.resendOtp`; `SpJwtAuth.otp` is now one cached instance so a captured challenge id survives to verify (J4).
- Added: synchronous `SpJwtAuth.currentSession`, `isAuthenticated`, `userId`, `accessTokenSync` (no I/O, never refreshes) and `addListener(listener)` (returns a remover), notified after restore, login, refresh, logout and cross-tab sync with the snapshot already updated; listener exceptions are isolated (J5).
- Added: `KeyValueStorage`, `StorageKeys` (overridable key names, neutral defaults) and `KeyValueTokenStore`, a pure-Dart `TokenStore` over any string key-value storage; `expiresAt` reads ISO-8601 or epoch seconds and is written as ISO-8601 UTC (J1).
- Added: companion package `sp_jwt_auth_flutter` (`SecureStorageTokenStore`, `SpAuthListenable`) in the monorepo; not published yet (J1, J5).
- Docs: README aligned with 0.1.0 (`^0.1.0` install), new "Flutter mobile" guide (storage, `relativeToBase`, `sp_laravel_api` pairing, `attach(dio)` warning), compile-checked `example/mobile_example.dart`, README consistency test (J7).

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
