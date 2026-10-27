import 'claims.dart';
import 'errors.dart';
import 'token_store.dart';

/// Sealed representation of user authentication state.
sealed class AuthState {
  const AuthState();
}

/// User is not authenticated.
class Anonymous extends AuthState {
  const Anonymous();

  @override
  String toString() => 'AuthState.Anonymous';
}

/// Session is being restored from asynchronous persistent storage.
class Restoring extends AuthState {
  const Restoring();

  @override
  String toString() => 'AuthState.Restoring';
}

/// User is successfully authenticated with valid session and claims.
class Authenticated extends AuthState {
  final Map<String, dynamic> user;
  final JwtClaims claims;

  const Authenticated({required this.user, required this.claims});

  @override
  String toString() => 'AuthState.Authenticated(sub: ${claims.sub})';
}

/// Sealed result of a login attempt.
sealed class LoginResult {
  const LoginResult();
}

/// Login completed successfully with full session.
class AuthenticatedResult extends LoginResult {
  final StoredSession session;
  const AuthenticatedResult(this.session);

  @override
  String toString() => 'LoginResult.Authenticated';
}

/// Login requires a second factor verification challenge.
class SecondFactorRequiredResult extends LoginResult {
  final String challengeId;
  const SecondFactorRequiredResult(this.challengeId);

  @override
  String toString() =>
      'LoginResult.SecondFactorRequired(challengeId: $challengeId)';
}

/// Reasons why an authentication session ended.
enum SessionEndReason {
  /// User explicitly triggered logout.
  manualLogout,

  /// Another browser tab or window broadcast a logout.
  crossTabLogout,

  /// Access token expired and no refresh token was present or available.
  tokenExpired,

  /// Token refresh endpoint returned a definitive 401 or token reuse rejection.
  refreshRejected,

  /// Persistent storage was cleared externally.
  storageCleared,

  /// Unknown reason or unclassified session end.
  unknown;

  /// Serialized wire / string value.
  String get value {
    switch (this) {
      case SessionEndReason.manualLogout:
        return 'manual_logout';
      case SessionEndReason.crossTabLogout:
        return 'cross_tab_logout';
      case SessionEndReason.tokenExpired:
        return 'token_expired';
      case SessionEndReason.refreshRejected:
        return 'refresh_rejected';
      case SessionEndReason.storageCleared:
        return 'storage_cleared';
      case SessionEndReason.unknown:
        return 'unknown';
    }
  }

  /// Parse a wire string into [SessionEndReason].
  static SessionEndReason fromString(String raw) {
    switch (raw) {
      case 'manual_logout':
        return SessionEndReason.manualLogout;
      case 'cross_tab_logout':
        return SessionEndReason.crossTabLogout;
      case 'token_expired':
        return SessionEndReason.tokenExpired;
      case 'refresh_rejected':
        return SessionEndReason.refreshRejected;
      case 'storage_cleared':
        return SessionEndReason.storageCleared;
      default:
        return SessionEndReason.unknown;
    }
  }
}

/// Sealed stream events representing lifecycle auth occurrences.
sealed class AuthEvent {
  const AuthEvent();
}

/// Session has been terminated due to expiry, rotation failure, or revocation.
class SessionEnded extends AuthEvent {
  final String reason;
  final SessionEndReason? _endReason;

  const SessionEnded(this.reason, {SessionEndReason? endReason})
    : _endReason = endReason;

  const SessionEnded.manualLogout([this.reason = 'manual_logout'])
    : _endReason = SessionEndReason.manualLogout;

  const SessionEnded.crossTabLogout([this.reason = 'cross_tab_logout'])
    : _endReason = SessionEndReason.crossTabLogout;

  const SessionEnded.tokenExpired([this.reason = 'token_expired'])
    : _endReason = SessionEndReason.tokenExpired;

  const SessionEnded.refreshRejected([this.reason = 'refresh_rejected'])
    : _endReason = SessionEndReason.refreshRejected;

  const SessionEnded.storageCleared([this.reason = 'storage_cleared'])
    : _endReason = SessionEndReason.storageCleared;

  /// Typed reason why the session ended.
  SessionEndReason get endReason =>
      _endReason ?? SessionEndReason.fromString(reason);

  @override
  String toString() =>
      'AuthEvent.SessionEnded(reason: $reason, endReason: $endReason)';

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is SessionEnded &&
          runtimeType == other.runtimeType &&
          reason == other.reason &&
          endReason == other.endReason;

  @override
  int get hashCode => Object.hash(reason, endReason);
}

/// Session has been refreshed with new tokens.
class Refreshed extends AuthEvent {
  final StoredSession session;
  const Refreshed(this.session);

  @override
  String toString() => 'AuthEvent.Refreshed';
}

/// User explicitly requested logout.
class LoggedOut extends AuthEvent {
  const LoggedOut();

  @override
  String toString() => 'AuthEvent.LoggedOut';
}

/// An error occurred during auth operations or storage reads.
class AuthErrorOccurred extends AuthEvent {
  final SpAuthError error;
  const AuthErrorOccurred(this.error);

  @override
  String toString() => 'AuthEvent.AuthErrorOccurred($error)';
}
