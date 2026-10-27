import 'dart:async';
import 'dart:convert';
import 'package:dio/dio.dart';
import 'package:sp_jwt_auth/sp_jwt_auth.dart';
import 'package:test/test.dart';

void main() {
  late MemoryTokenStore store;
  late Dio mockDio;
  late SpJwtAuth auth;
  late Future<Response<dynamic>> Function(RequestOptions options)
  responseHandler;

  setUp(() {
    store = MemoryTokenStore();
    mockDio = Dio(BaseOptions(baseUrl: 'https://api.example.com'));
    mockDio.httpClientAdapter = _MockAdapter((options) async {
      return responseHandler(options);
    });

    auth = SpJwtAuth(
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
      dio: mockDio,
      refreshAhead: const Duration(seconds: 60),
    );
  });

  test(
    'onResumed() proactively refreshes expired or expiring token once',
    () async {
      final session = StoredSession(
        accessToken: 'expiring_token',
        refreshToken: 'valid_refresh',
        expiresAt: DateTime.now().toUtc().add(const Duration(seconds: 15)),
      );
      await store.write(session);
      await auth.restore();

      var refreshCount = 0;
      responseHandler = (options) async {
        if (options.path.contains('/auth/refresh')) {
          refreshCount++;
          return Response<dynamic>(
            requestOptions: options,
            statusCode: 200,
            data: {
              'success': true,
              'data': {
                'access_token': 'new_on_resumed_token',
                'refresh_token': 'new_refresh',
                'expires_at':
                    DateTime.now()
                        .toUtc()
                        .add(const Duration(hours: 1))
                        .millisecondsSinceEpoch ~/
                    1000,
              },
            },
          );
        }
        return Response<dynamic>(requestOptions: options, statusCode: 404);
      };

      auth.onResumed();
      // Allow async background refresh to execute
      for (var i = 0; i < 50 && refreshCount == 0; i++) {
        await Future<void>.delayed(const Duration(milliseconds: 10));
      }

      expect(refreshCount, equals(1));
      expect(await auth.accessToken(), equals('new_on_resumed_token'));
    },
  );

  test(
    'changes stream emits only on real state transitions and does not replay',
    () async {
      final stateTransitions = <AuthState>[];
      final sub = auth.changes.listen(stateTransitions.add);

      // Initial state is Anonymous; calling restore when empty does NOT re-emit Anonymous
      await auth.restore();
      expect(stateTransitions, isEmpty);

      // Login emits Authenticated
      responseHandler = (options) async {
        return Response<dynamic>(
          requestOptions: options,
          statusCode: 200,
          data: {
            'success': true,
            'data': {
              'access_token': 'logged_in_token',
              'refresh_token': 'refresh_token',
              'expires_at':
                  DateTime.now()
                      .toUtc()
                      .add(const Duration(hours: 1))
                      .millisecondsSinceEpoch ~/
                  1000,
              'user': {'id': 42},
            },
          },
        );
      };

      final result = await auth.login({
        'email': 'test@example.com',
        'password': 'secret',
      });
      expect(result, isA<AuthenticatedResult>());
      await Future<void>.delayed(Duration.zero);
      expect(stateTransitions.length, equals(1));
      expect(stateTransitions.first, isA<Authenticated>());

      // Second subscription does NOT get replayed past events
      final lateTransitions = <AuthState>[];
      final sub2 = auth.changes.listen(lateTransitions.add);
      expect(lateTransitions, isEmpty);

      await sub.cancel();
      await sub2.cancel();
    },
  );

  test(
    'login() returns SecondFactorRequiredResult when MFA is challenged',
    () async {
      responseHandler = (options) async {
        return Response<dynamic>(
          requestOptions: options,
          statusCode: 200,
          data: {
            'success': true,
            'mfa_required': true,
            'challenge_id': 'mfa_challenge_xyz',
          },
        );
      };

      final result = await auth.login({
        'email': 'mfa@example.com',
        'password': 'secret',
      });
      expect(result, isA<SecondFactorRequiredResult>());
      expect(
        (result as SecondFactorRequiredResult).challengeId,
        equals('mfa_challenge_xyz'),
      );
      // State remains Anonymous
      expect(auth.state, isA<Anonymous>());
    },
  );

  test('whoami() retrieves current user profile with auth header', () async {
    await store.write(
      StoredSession(
        accessToken: 'valid_whoami_token',
        expiresAt: DateTime.now().toUtc().add(const Duration(hours: 1)),
      ),
    );
    await auth.restore();

    RequestOptions? capturedWhoami;
    responseHandler = (options) async {
      if (options.path.contains('/auth/whoami')) {
        capturedWhoami = options;
        return Response<dynamic>(
          requestOptions: options,
          statusCode: 200,
          data: {
            'data': {'id': 123, 'email': 'user@example.com'},
          },
        );
      }
      return Response<dynamic>(requestOptions: options, statusCode: 404);
    };

    final profile = await auth.whoami();
    expect(
      capturedWhoami?.headers['Authorization'],
      equals('Bearer valid_whoami_token'),
    );
    expect(profile['data']['id'], equals(123));
  });
}

class _MockAdapter implements HttpClientAdapter {
  final Future<Response<dynamic>> Function(RequestOptions options) handler;
  _MockAdapter(this.handler);

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<List<int>>? requestStream,
    Future<void>? cancelFuture,
  ) async {
    try {
      final res = await handler(options);
      final data = res.data;
      final String jsonStr = data is String ? data : jsonEncode(data);
      return ResponseBody.fromString(
        jsonStr,
        res.statusCode ?? 200,
        headers: {
          Headers.contentTypeHeader: [Headers.jsonContentType],
        },
      );
    } on DioException catch (e) {
      if (e.response != null) {
        final d = e.response?.data;
        final jsonStr = d is String ? d : jsonEncode(d);
        return ResponseBody.fromString(
          jsonStr,
          e.response?.statusCode ?? 500,
          headers: {
            Headers.contentTypeHeader: [Headers.jsonContentType],
          },
        );
      }
      rethrow;
    }
  }

  @override
  void close({bool force = false}) {}
}
