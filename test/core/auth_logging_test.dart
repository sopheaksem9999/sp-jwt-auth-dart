import 'dart:convert';
import 'package:dio/dio.dart';
import 'package:sp_jwt_auth/sp_jwt_auth.dart';
import 'package:test/test.dart';

typedef _Reply = ({int status, Object? body, Map<String, String> headers});

class _Adapter implements HttpClientAdapter {
  final _Reply Function(RequestOptions) handler;
  final List<RequestOptions> seen = [];
  _Adapter(this.handler);

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<List<int>>? requestStream,
    Future<void>? cancelFuture,
  ) async {
    seen.add(options);
    final r = handler(options);
    return ResponseBody.fromString(
      jsonEncode(r.body),
      r.status,
      headers: {
        Headers.contentTypeHeader: [Headers.jsonContentType],
        for (final e in r.headers.entries) e.key: [e.value],
      },
    );
  }

  @override
  void close({bool force = false}) {}
}

_Reply _ok([Object? body, Map<String, String> headers = const {}]) => (
  status: 200,
  body:
      body ??
      {
        'success': true,
        'data': {
          'access_token': 'at-secret',
          'refresh_token': 'rt-secret',
          'expires_at': 4102444800,
          'user': {'id': 1, 'name': 'Ada'},
        },
        'meta': {'request_id': 'rid-1'},
      },
  headers: headers,
);

StoredSession _session({int secondsLeft = 3600}) => StoredSession(
  accessToken: 'at-secret',
  refreshToken: 'rt-secret',
  expiresAt: DateTime.now().toUtc().add(Duration(seconds: secondsLeft)),
  user: {'id': 1},
);

SpJwtAuth _auth(
  _Adapter adapter, {
  MemoryTokenStore? store,
  AuthLogger? logger,
  bool logRequests = false,
}) {
  final dio = Dio(BaseOptions(baseUrl: 'https://api.example.com'));
  dio.httpClientAdapter = adapter;
  return SpJwtAuth(
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
    store: store ?? MemoryTokenStore(),
    dio: dio,
    logger: logger,
    logRequests: logRequests,
  );
}

void main() {
  test('no entry without logger and logRequests', () async {
    final entries = <AuthLogEntry>[];
    final a1 = _auth(
      _Adapter((_) => _ok()),
      logger: AuthLogger(sink: entries.add),
    );
    await a1.login({'email': 'ada@example.com', 'password': 'pw'});
    final a2 = _auth(_Adapter((_) => _ok()), logRequests: true);
    await a2.login({'email': 'ada@example.com', 'password': 'pw'});
    expect(entries, isEmpty);
  });

  group(
    'login, refresh, logout, whoami, OTP and MFA calls each produce one entry per attempt',
    () {
      final cases =
          <(String, String, String, Future<void> Function(SpJwtAuth))>[
            (
              'login',
              'POST',
              '/auth/login',
              (a) async =>
                  a.login({'email': 'ada@example.com', 'password': 'pw'}),
            ),
            ('refresh', 'POST', '/auth/refresh', (a) async => a.accessToken()),
            ('logout', 'POST', '/auth/logout', (a) => a.logout()),
            ('whoami', 'GET', '/auth/whoami', (a) async => a.whoami()),
            (
              'otp send',
              'POST',
              '/auth/otp/send',
              (a) => a.otp.sendOtp(identifier: 'ada@example.com'),
            ),
            (
              'otp verify',
              'POST',
              '/auth/otp/verify',
              (a) async =>
                  a.otp.verifyOtp(identifier: 'ada@example.com', code: '1'),
            ),
            (
              'mfa methods',
              'GET',
              '/auth/mfa/methods',
              (a) async => a.mfa.listMethods(challengeId: 'c1'),
            ),
            (
              'mfa challenge',
              'POST',
              '/auth/mfa/challenge',
              (a) async => a.mfa.challenge(challengeId: 'c1', method: 'sms'),
            ),
            (
              'mfa verify',
              'POST',
              '/auth/mfa/verify',
              (a) async => a.mfa.verify(challengeId: 'c1', code: '123456'),
            ),
            (
              'sessions list',
              'GET',
              '/auth/sessions',
              (a) async => a.sessions.list(),
            ),
            (
              'sessions revoke',
              'DELETE',
              '/auth/sessions/s1',
              (a) => a.sessions.revoke('s1'),
            ),
            (
              'sessions revokeOthers',
              'POST',
              '/auth/sessions/revoke-others',
              (a) => a.sessions.revokeOthers(),
            ),
            (
              'account updateProfile',
              'PUT',
              '/auth/account/profile',
              (a) async => a.account.updateProfile({'name': 'Ada'}),
            ),
            (
              'account changePassword',
              'POST',
              '/auth/account/change-password',
              (a) => a.account.changePassword(
                currentPassword: 'old',
                newPassword: 'new',
              ),
            ),
          ];

      for (final c in cases) {
        test(c.$1, () async {
          final entries = <AuthLogEntry>[];
          final store = MemoryTokenStore();
          await store.write(
            _session(secondsLeft: c.$1 == 'refresh' ? 10 : 3600),
          );
          final adapter = _Adapter((_) => _ok(null, {'X-Request-Id': 'abc'}));
          final auth = _auth(
            adapter,
            store: store,
            logger: AuthLogger(sink: entries.add),
            logRequests: true,
          );
          await auth.restore();
          entries.clear();
          adapter.seen.clear();
          await c.$4(auth);
          expect(entries, hasLength(1), reason: entries.join('\n'));
          expect(adapter.seen, hasLength(1));
          final e = entries.single;
          expect(e.method, c.$2);
          expect(e.path, c.$3);
          expect(e.status, 200);
          expect(e.attempt, 1);
          expect(e.requestId, 'abc');
          expect(e.code, isNull);
          expect(e.toString(), startsWith('${c.$2} ${c.$3} -> 200 '));
          expect(e.toString(), contains('rid=abc attempt=1'));
        });
      }
    },
  );

  test('a failed login (non-2xx) produces an entry with its status', () async {
    final entries = <AuthLogEntry>[];
    final auth = _auth(
      _Adapter(
        (_) => (
          status: 401,
          body: {'message': 'bad', 'error_code': 10002},
          headers: <String, String>{},
        ),
      ),
      logger: AuthLogger(sink: entries.add),
      logRequests: true,
    );
    await expectLater(
      auth.login({'email': 'ada@example.com', 'password': 'pw'}),
      throwsA(isA<DioException>()),
    );
    expect(entries, hasLength(1));
    expect(entries.single.status, 401);
    expect(entries.single.code, isNotNull);
    expect(entries.single.errorCode, 10002);
  });

  test('entries never contain headers, bodies or query strings', () async {
    final entries = <AuthLogEntry>[];
    final store = MemoryTokenStore();
    await store.write(_session());
    final auth = _auth(
      _Adapter((o) => _ok()),
      store: store,
      logger: AuthLogger(sink: entries.add),
      logRequests: true,
    );
    await auth.restore();
    await auth.login({'email': 'ada@example.com', 'password': 'hunter2-pw'});
    await auth.otp.verifyOtp(identifier: 'ada@example.com', code: '987654');
    await auth.mfa.listMethods(challengeId: 'challenge-xyz');
    await auth.whoami();
    // A caller-supplied URL with a query string and an Authorization header.
    await auth.send(
      'GET',
      'https://api.example.com/auth/whoami?token=query-secret',
      options: Options(headers: {'Authorization': 'Bearer header-secret'}),
    );
    await auth.logout();
    expect(entries.length, greaterThanOrEqualTo(6));
    const secrets = [
      'hunter2-pw',
      '987654',
      'at-secret',
      'rt-secret',
      'query-secret',
      'header-secret',
      'challenge-xyz',
      'token=',
      'Bearer',
      'ada@example.com',
    ];
    for (final e in entries) {
      final all = [
        e.toString(),
        e.method,
        e.path,
        '${e.status}',
        '${e.duration}',
        '${e.requestId}',
        '${e.attempt}',
        '${e.code}',
        '${e.errorCode}',
      ].join('|');
      for (final s in secrets) {
        expect(all, isNot(contains(s)), reason: 'leaked $s in $all');
      }
      expect(e.path, isNot(contains('?')));
    }
  });

  test('a failing 200 envelope entry carries code and errorCode', () async {
    final entries = <AuthLogEntry>[];
    final auth = _auth(
      _Adapter(
        (_) => _ok({
          'success': false,
          'message': 'Invalid credentials',
          'error_code': 20001,
          'meta': {'request_id': 'rid-9'},
        }),
      ),
      logger: AuthLogger(sink: entries.add),
      logRequests: true,
    );
    await expectLater(
      auth.login({'email': 'ada@example.com', 'password': 'pw'}),
      throwsA(isA<SpAuthError>()),
    );
    expect(entries, hasLength(1));
    final e = entries.single;
    expect(e.status, 200);
    expect(e.code, SpAuthErrorCode.unauthenticated);
    expect(e.errorCode, 20001);
    expect(e.requestId, 'rid-9');
    expect(e.toString(), contains('errorCode=20001'));
  });

  test('a throwing sink does not change the request result', () async {
    var calls = 0;
    final auth = _auth(
      _Adapter((_) => _ok()),
      logger: AuthLogger(
        sink: (_) {
          calls++;
          throw StateError('sink boom');
        },
      ),
      logRequests: true,
    );
    final result = await auth.login({
      'email': 'ada@example.com',
      'password': 'pw',
    });
    expect(result, isA<AuthenticatedResult>());
    expect(calls, 1);

    final failing = _auth(
      _Adapter(
        (_) =>
            (status: 500, body: {'message': 'x'}, headers: <String, String>{}),
      ),
      logger: AuthLogger(sink: (_) => throw StateError('sink boom')),
      logRequests: true,
    );
    await expectLater(
      failing.login({'email': 'ada@example.com', 'password': 'pw'}),
      throwsA(isA<DioException>()),
    );
  });
}
