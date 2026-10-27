import 'package:sp_jwt_auth/src/errors.dart';
import 'package:test/test.dart';

void main() {
  test('SpAuthError properties and string representation', () {
    const error = SpAuthError(
      code: SpAuthErrorCode.unauthenticated,
      message: 'Token expired',
      status: 401,
      errorCode: 10002,
      requestId: 'req-123',
    );

    expect(error.code, equals(SpAuthErrorCode.unauthenticated));
    expect(error.message, equals('Token expired'));
    expect(error.status, equals(401));
    expect(error.errorCode, equals(10002));
    expect(error.requestId, equals('req-123'));
    expect(error.toString(), contains('SpAuthError(unauthenticated): Token expired [status: 401, error_code: 10002, request_id: req-123]'));
  });
}
