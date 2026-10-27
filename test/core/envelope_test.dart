import 'dart:convert';
import 'package:dio/dio.dart';
import 'package:sp_jwt_auth/sp_jwt_auth.dart';
import 'package:sp_jwt_auth/src/envelope.dart';
import 'package:test/test.dart';

void main() {
  late MemoryTokenStore store;
  late Dio dio;
  late Map<String, dynamic> nextBody;

  const failure = {
    'success': false,
    'error_code': 10004,
    'message': 'Invalid OTP code',
    'meta': {'request_id': 'r1'},
  };

  Map<String, dynamic> success(String at) => {
    'success': true,
    'data': {
      'access_token': at,
      'refresh_token': 'rt',
      'expires_at':
          DateTime.now()
              .toUtc()
              .add(const Duration(hours: 1))
              .millisecondsSinceEpoch ~/
          1000,
      'user': {'id': 1},
    },
  };

  setUp(() {
    store = MemoryTokenStore();
    dio = Dio(BaseOptions(baseUrl: 'https://api.example.com'));
    dio.httpClientAdapter = _Adapter(() => nextBody);
  });

  SpJwtAuth createAuth() => SpJwtAuth(
    baseUrl: Uri.parse('https://api.example.com'),
    endpoints: Endpoints(
      login: '/auth/login',
      refresh: '/auth/refresh',
      logout: '/auth/logout',
      whoami: '/auth/whoami',
      parseSession: (data) {
        final map =
            (data as Map<String, dynamic>)['data'] as Map<String, dynamic>;
        return StoredSession(
          accessToken: map['access_token'] as String,
          refreshToken: map['refresh_token'] as String?,
          expiresAt: DateTime.fromMillisecondsSinceEpoch(
            (map['expires_at'] as int) * 1000,
            isUtc: true,
          ),
          user: map['user'] as Map<String, dynamic>?,
        );
      },
    ),
    store: store,
    dio: dio,
  );

  void expectEnvelopeError(Object? e) {
    expect(e, isA<SpAuthError>());
    final err = e as SpAuthError;
    expect(err.message, 'Invalid OTP code');
    expect(err.errorCode, 10004);
    expect(err.requestId, 'r1');
  }

  test('login throws SpAuthError on 200 success:false', () async {
    final auth = createAuth();
    nextBody = failure;
    Object? caught;
    try {
      await auth.login({'email': 'a@example.com', 'password': 'x'});
    } catch (e) {
      caught = e;
    }
    expectEnvelopeError(caught);
    expect(await store.read(), isNull);
    expect(auth.state, isA<Anonymous>());
  });

  test('verifyOtp throws SpAuthError on 200 success:false', () async {
    final auth = createAuth();
    nextBody = failure;
    Object? caught;
    try {
      await auth.otp.verifyOtp(identifier: 'a@example.com', code: '000000');
    } catch (e) {
      caught = e;
    }
    expectEnvelopeError(caught);
    expect(await store.read(), isNull);
    expect(auth.state, isA<Anonymous>());
  });

  test(
    'sendOtp and resendOtp throw SpAuthError on 200 success:false',
    () async {
      var captured = 0;
      final auth = SpJwtAuth(
        baseUrl: Uri.parse('https://api.example.com'),
        endpoints: const Endpoints(otpResend: '/auth/otp/resend'),
        store: store,
        otpOptions: OtpOptions(
          challengeIdFrom: (_) {
            captured++;
            return 'stale';
          },
        ),
        dio: dio,
      );
      nextBody = failure;
      for (final call in [
        () => auth.otp.sendOtp(identifier: 'a@example.com'),
        () => auth.otp.resendOtp(identifier: 'a@example.com'),
      ]) {
        Object? caught;
        try {
          await call();
        } catch (e) {
          caught = e;
        }
        expectEnvelopeError(caught);
      }
      expect(captured, 0);
    },
  );

  test('second sendOtp without an id does not reuse the first id', () async {
    final sent = <dynamic>[];
    final auth = SpJwtAuth(
      baseUrl: Uri.parse('https://api.example.com'),
      endpoints: Endpoints(
        parseSession: (data) =>
            StoredSession(accessToken: 'at', refreshToken: 'rt'),
      ),
      store: store,
      otpOptions: OtpOptions(
        challengeIdFrom: (r) => (r as Map)['challenge'] as String?,
        verifyBody: (id, code, challengeId) {
          sent.add(challengeId);
          return {'code': code};
        },
      ),
      dio: dio,
    );
    nextBody = {'success': true, 'challenge': 'c1'};
    await auth.otp.sendOtp(identifier: 'a');
    nextBody = {'success': true};
    await auth.otp.sendOtp(identifier: 'a');
    await auth.otp.verifyOtp(identifier: 'a', code: '1');
    expect(sent, [null]);
  });

  test('verify after a successful verify does not send the old id', () async {
    final sent = <dynamic>[];
    final auth = SpJwtAuth(
      baseUrl: Uri.parse('https://api.example.com'),
      endpoints: Endpoints(
        parseSession: (data) =>
            StoredSession(accessToken: 'at', refreshToken: 'rt'),
      ),
      store: store,
      otpOptions: OtpOptions(
        challengeIdFrom: (r) => (r as Map)['challenge'] as String?,
        verifyBody: (id, code, challengeId) {
          sent.add(challengeId);
          return {'code': code};
        },
      ),
      dio: dio,
    );
    nextBody = {'success': true, 'challenge': 'c1'};
    await auth.otp.sendOtp(identifier: 'a');
    await auth.otp.verifyOtp(identifier: 'a', code: '1');
    await auth.otp.verifyOtp(identifier: 'a', code: '2');
    expect(sent, ['c1', null]);
  });

  test('mfa verify throws SpAuthError on 200 success:false', () async {
    final auth = createAuth();
    nextBody = {
      'success': false,
      'error_code': 10004,
      'message': 'Invalid code',
    };
    await expectLater(
      auth.mfa.verify(challengeId: 'c', code: '1'),
      throwsA(
        isA<SpAuthError>()
            .having((e) => e.message, 'message', 'Invalid code')
            .having((e) => e.errorCode, 'errorCode', 10004),
      ),
    );
    expect(await store.read(), isNull);
    expect(auth.state, isA<Anonymous>());
  });

  test('failed login leaves existing session intact', () async {
    final auth = createAuth();
    nextBody = success('first_at');
    await auth.login({'email': 'a@example.com', 'password': 'x'});
    expect((await store.read())!.accessToken, 'first_at');

    nextBody = failure;
    await expectLater(
      auth.login({'email': 'a@example.com', 'password': 'bad'}),
      throwsA(isA<SpAuthError>()),
    );
    expect((await store.read())!.accessToken, 'first_at');
    expect(auth.state, isA<Authenticated>());
  });

  test('refresh path still ends session on 10002 via shared helper', () async {
    await store.write(
      StoredSession(
        accessToken: 'old',
        refreshToken: 'rt',
        expiresAt: DateTime.now().toUtc().add(const Duration(seconds: 5)),
      ),
    );
    final auth = createAuth();
    await auth.restore();
    nextBody = {
      'success': false,
      'error_code': 10002,
      'message': 'Unauthenticated',
    };
    await expectLater(auth.accessToken(), throwsA(isA<SpAuthError>()));
    expect(auth.state, isA<Anonymous>());
  });

  test('refresh with other success:false throws envelope error', () async {
    await store.write(
      StoredSession(
        accessToken: 'old',
        refreshToken: 'rt',
        expiresAt: DateTime.now().toUtc().add(const Duration(seconds: 5)),
      ),
    );
    final auth = createAuth();
    await auth.restore();
    nextBody = failure;
    Object? caught;
    try {
      await auth.accessToken();
    } catch (e) {
      caught = e;
    }
    expectEnvelopeError(caught);
  });

  test('successful login unchanged', () async {
    final auth = createAuth();
    nextBody = success('at1');
    final result = await auth.login({'email': 'a@example.com'});
    expect(result, isA<AuthenticatedResult>());
    expect((await store.read())!.accessToken, 'at1');
    expect(auth.state, isA<Authenticated>());
  });

  group('throwIfEnvelopeFailure', () {
    test('ignores non-map and non-failure bodies', () {
      throwIfEnvelopeFailure(null);
      throwIfEnvelopeFailure('x');
      throwIfEnvelopeFailure(<String, dynamic>{'success': true});
      throwIfEnvelopeFailure(<String, dynamic>{});
    });

    test('accepts a numeric-string error_code', () {
      expect(
        () => throwIfEnvelopeFailure(<String, dynamic>{
          'success': false,
          'error_code': '10004',
        }),
        throwsA(isA<SpAuthError>().having((e) => e.errorCode, 'c', 10004)),
      );
    });

    test('defaults message when absent', () {
      expect(
        () => throwIfEnvelopeFailure(<String, dynamic>{'success': false}),
        throwsA(
          isA<SpAuthError>()
              .having((e) => e.message, 'message', 'Request failed')
              .having((e) => e.code, 'code', SpAuthErrorCode.unauthenticated)
              .having((e) => e.errorCode, 'errorCode', isNull)
              .having((e) => e.requestId, 'requestId', isNull),
        ),
      );
    });
  });
}

class _Adapter implements HttpClientAdapter {
  final Map<String, dynamic> Function() body;
  _Adapter(this.body);

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<List<int>>? requestStream,
    Future<void>? cancelFuture,
  ) async {
    return ResponseBody.fromString(
      jsonEncode(body()),
      200,
      headers: {
        Headers.contentTypeHeader: [Headers.jsonContentType],
      },
    );
  }

  @override
  void close({bool force = false}) {}
}
