import 'token_store.dart';

/// Configured authentication endpoints and session response parser.
///
/// Endpoint paths (including those used by the otp, mfa, account and sessions
/// modules) are resolved against `baseUrl`. By default ([relativeToBase] is
/// false) a path starting with `/` replaces any path on `baseUrl`, so
/// `https://h/api/v1` + `/auth/login` is `https://h/auth/login`. When
/// [relativeToBase] is true, paths are appended beneath the `baseUrl` path:
/// `https://h/api/v1/auth/login`.
class Endpoints {
  /// Path for user login (default `/auth/login`).
  final String login;

  /// Path for refreshing access tokens (default `/auth/refresh`).
  final String refresh;

  /// Path for logging out / revoking session (default `/auth/logout`).
  final String logout;

  /// Path for fetching current user profile (default `/auth/whoami`).
  final String whoami;

  /// Path for sending a one-time password (default `/auth/otp/send`).
  final String otpSend;

  /// Path for verifying a one-time password (default `/auth/otp/verify`).
  final String otpVerify;

  /// Path for resending a one-time password; null (default) disables
  /// `OtpModule.resendOtp`.
  final String? otpResend;

  /// Whether endpoint paths are joined beneath the path of `baseUrl`
  /// (true) or resolved as absolute paths from its origin (false, default).
  final bool relativeToBase;

  /// Transformer that extracts [StoredSession] from the backend response body.
  ///
  /// Defaults to [StoredSession.fromEnvelope] (envelope or flat body).
  final StoredSession Function(dynamic responseData) parseSession;

  /// Creates configured authentication [Endpoints].
  const Endpoints({
    this.login = '/auth/login',
    this.refresh = '/auth/refresh',
    this.logout = '/auth/logout',
    this.whoami = '/auth/whoami',
    this.otpSend = '/auth/otp/send',
    this.otpVerify = '/auth/otp/verify',
    this.otpResend,
    this.relativeToBase = false,
    this.parseSession = _defaultParseSession,
  });
}

StoredSession _defaultParseSession(dynamic body) =>
    StoredSession.fromEnvelope(body);

/// Customizes OTP request bodies and challenge-id handling.
///
/// Every field is optional; the defaults reproduce the 0.1.0 request bodies.
class OtpOptions {
  /// Builds the send (and resend) request body.
  final Map<String, dynamic> Function(String identifier, String? channel)?
  sendBody;

  /// Builds the verify request body; [challengeId] is the id captured by
  /// [challengeIdFrom] from the last send response, if any.
  final Map<String, dynamic> Function(
    String identifier,
    String code,
    String? challengeId,
  )?
  verifyBody;

  /// Extracts a challenge id from the decoded send response body.
  final String? Function(dynamic sendResponse)? challengeIdFrom;

  /// Creates [OtpOptions].
  const OtpOptions({this.sendBody, this.verifyBody, this.challengeIdFrom});
}
