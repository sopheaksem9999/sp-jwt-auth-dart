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
      SpAuthError(code: SpAuthErrorCode.storageError, message: 'Keychain locked'),
    );
    expect(error, isA<AuthEvent>());
    expect(error.error.code, equals(SpAuthErrorCode.storageError));
  });
}
