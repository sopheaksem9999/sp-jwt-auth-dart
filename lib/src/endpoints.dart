import 'token_store.dart';

/// Configured authentication endpoints and session response parser.
class Endpoints {
  /// Path for user login (default `/auth/login`).
  final String login;

  /// Path for refreshing access tokens (default `/auth/refresh`).
  final String refresh;

  /// Path for logging out / revoking session (default `/auth/logout`).
  final String logout;

  /// Path for fetching current user profile (default `/auth/whoami`).
  final String whoami;

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
    this.parseSession = _defaultParseSession,
  });
}

StoredSession _defaultParseSession(dynamic body) =>
    StoredSession.fromEnvelope(body);
