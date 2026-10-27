import 'package:sp_jwt_auth/src/claims.dart';
import 'package:sp_jwt_auth/src/errors.dart';
import 'package:test/test.dart';

void main() {
  test('parse extracts sub, exp, scopes, sid and custom company claim', () {
    const jwt =
        'header.eyJzdWIiOiIxMjMiLCJleHAiOjE4OTM0NTYwMDAsInNjb3BlcyI6WyJyZWFkIiwid3JpdGUiXSwic2lkIjoiYWJjIiwiY29tcGFueV9pZCI6Ijk5OSJ9.sig';
    final claims = JwtClaims.parse(jwt, companyClaim: 'company_id');
    expect(claims.sub, equals('123'));
    expect(
      claims.exp,
      equals(DateTime.fromMillisecondsSinceEpoch(1893456000000, isUtc: true)),
    );
    expect(claims.scopes, equals(['read', 'write']));
    expect(claims.sid, equals('abc'));
    expect(claims.companyId, equals('999'));
  });

  test('parse handles unpadded and URL-safe base64 characters', () {
    // payload {"sub":"user_1","custom":"-_"}
    // eyJzdWIiOiJ1c2VyXzEiLCJjdXN0b20iOiItXyJ9
    const jwt = 'h.eyJzdWIiOiJ1c2VyXzEiLCJjdXN0b20iOiItXyJ9.s';
    final claims = JwtClaims.parse(jwt);
    expect(claims.sub, equals('user_1'));
    expect(claims.raw['custom'], equals('-_'));
  });

  test('parse malformed token throws SpAuthError invalidToken', () {
    expect(
      () => JwtClaims.parse('not.a.valid.jwt.parts'),
      throwsA(
        isA<SpAuthError>().having(
          (e) => e.code,
          'code',
          SpAuthErrorCode.invalidToken,
        ),
      ),
    );
  });
}
