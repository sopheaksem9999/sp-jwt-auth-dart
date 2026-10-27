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

/// Sealed stream events representing lifecycle auth occurrences.
sealed class AuthEvent {
  const AuthEvent();
}

/// Session has been terminated due to expiry, rotation failure, or revocation.
class SessionEnded extends AuthEvent {
  final String reason;
  const SessionEnded(this.reason);

  @override
  String toString() => 'AuthEvent.SessionEnded(reason: $reason)';
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
