import 'package:sp_jwt_auth/src/claims.dart';
import 'package:sp_jwt_auth/src/errors.dart';
import 'package:sp_jwt_auth/src/session.dart';
import 'package:test/test.dart';

void main() {
  test('AuthState sealed hierarchy instantiation', () {
    const anonymous = Anonymous();
    expect(anonymous, isA<AuthState>());

    const restoring = Restoring();
    expect(restoring, isA<AuthState>());

    final claims = JwtClaims(raw: {'sub': '1'}, sub: '1');
    final authenticated = Authenticated(user: {'id': 1}, claims: claims);
    expect(authenticated, isA<AuthState>());
    expect(authenticated.user['id'], equals(1));
    expect(authenticated.claims.sub, equals('1'));
  });

  test('AuthEvent sealed hierarchy instantiation', () {
    const ended = SessionEnded('Token reuse detected');
    expect(ended, isA<AuthEvent>());
    expect(ended.reason, equals('Token reuse detected'));

    const loggedOut = LoggedOut();
    expect(loggedOut, isA<AuthEvent>());

    const error = AuthErrorOccurred(
      SpAuthError(
        code: SpAuthErrorCode.storageError,
        message: 'Keychain locked',
      ),
    );
    expect(error, isA<AuthEvent>());
    expect(error.error.code, equals(SpAuthErrorCode.storageError));
  });

  test('SessionEndReason values and SessionEnded constructors', () {
    expect(SessionEndReason.manualLogout.value, equals('manual_logout'));
    expect(SessionEndReason.crossTabLogout.value, equals('cross_tab_logout'));
    expect(SessionEndReason.tokenExpired.value, equals('token_expired'));
    expect(SessionEndReason.refreshRejected.value, equals('refresh_rejected'));
    expect(SessionEndReason.storageCleared.value, equals('storage_cleared'));
    expect(SessionEndReason.unknown.value, equals('unknown'));

    expect(
      SessionEndReason.fromString('manual_logout'),
      equals(SessionEndReason.manualLogout),
    );
    expect(
      SessionEndReason.fromString('cross_tab_logout'),
      equals(SessionEndReason.crossTabLogout),
    );
    expect(
      SessionEndReason.fromString('token_expired'),
      equals(SessionEndReason.tokenExpired),
    );
    expect(
      SessionEndReason.fromString('refresh_rejected'),
      equals(SessionEndReason.refreshRejected),
    );
    expect(
      SessionEndReason.fromString('storage_cleared'),
      equals(SessionEndReason.storageCleared),
    );
    expect(
      SessionEndReason.fromString('something_else'),
      equals(SessionEndReason.unknown),
    );

    const ended1 = SessionEnded.manualLogout();
    expect(ended1.endReason, equals(SessionEndReason.manualLogout));
    expect(ended1.reason, equals('manual_logout'));

    const ended2 = SessionEnded.crossTabLogout();
    expect(ended2.endReason, equals(SessionEndReason.crossTabLogout));

    const ended3 = SessionEnded('refresh_rejected');
    expect(ended3.endReason, equals(SessionEndReason.refreshRejected));
  });
}
