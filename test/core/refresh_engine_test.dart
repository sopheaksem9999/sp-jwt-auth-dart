import 'dart:async';
import 'dart:convert';
import 'package:dio/dio.dart';
import 'package:sp_jwt_auth/sp_jwt_auth.dart';
import 'package:test/test.dart';

import '../support/until.dart';

void main() {
  late MemoryTokenStore store;
  late Dio mockDio;
  late List<RequestOptions> capturedRequests;
  late Future<Response<dynamic>> Function(RequestOptions options)
  responseHandler;

  setUp(() {
    store = MemoryTokenStore();
    capturedRequests = [];
    mockDio = Dio(BaseOptions(baseUrl: 'https://api.example.com'));
    mockDio.httpClientAdapter = _MockAdapter((options) async {
      capturedRequests.add(options);
      return responseHandler(options);
    });
  });

  Endpoints createEndpoints() {
    return Endpoints(
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
    );
  }

  test('single-flight refresh deduplicates parallel calls', () async {
    // Initial session expires in 10s (refreshAhead is 60s, so proactive refresh needed)
    final initialSession = StoredSession(
      accessToken: 'old_at',
      refreshToken: 'valid_rt',
      expiresAt: DateTime.now().toUtc().add(const Duration(seconds: 10)),
      user: {'id': 1},
    );
    await store.write(initialSession);

    var refreshCallCount = 0;
    responseHandler = (options) async {
      if (options.path.contains('/auth/refresh')) {
        refreshCallCount++;
        await Future<void>.delayed(const Duration(milliseconds: 30));
        return Response<dynamic>(
          requestOptions: options,
          statusCode: 200,
          data: {
            'success': true,
            'data': {
              'access_token': 'new_at_123',
              'refresh_token': 'new_rt_456',
              'expires_at':
                  DateTime.now()
                      .toUtc()
                      .add(const Duration(hours: 1))
                      .millisecondsSinceEpoch ~/
                  1000,
              'user': {'id': 1},
            },
          },
        );
      }
      return Response<dynamic>(requestOptions: options, statusCode: 404);
    };

    final auth = SpJwtAuth(
      baseUrl: Uri.parse('https://api.example.com'),
      endpoints: createEndpoints(),
      store: store,
      dio: mockDio,
      refreshAhead: const Duration(seconds: 60),
    );
    await auth.restore();

    // Fire 3 parallel accessToken calls
    final results = await Future.wait([
      auth.accessToken(),
      auth.accessToken(),
      auth.accessToken(),
    ]);

    expect(results, equals(['new_at_123', 'new_at_123', 'new_at_123']));
    expect(refreshCallCount, equals(1));
    final updated = await store.read();
    expect(updated?.accessToken, equals('new_at_123'));
  });

  test(
    'HTTP 500 with unauthenticated message triggers definitive SessionEnded',
    () async {
      final initialSession = StoredSession(
        accessToken: 'old_at',
        refreshToken: 'reused_rt',
        expiresAt: DateTime.now().toUtc().subtract(const Duration(seconds: 10)),
      );
      await store.write(initialSession);

      responseHandler = (options) async {
        return Response<dynamic>(
          requestOptions: options,
          statusCode: 500,
          data: {
            'message':
                'Unauthenticated: refresh token already used or expired.',
          },
        );
      };

      final auth = SpJwtAuth(
        baseUrl: Uri.parse('https://api.example.com'),
        endpoints: createEndpoints(),
        store: store,
        dio: mockDio,
      );
      await auth.restore();

      final events = <AuthEvent>[];
      auth.events.listen(events.add);

      await expectLater(auth.accessToken(), throwsA(isA<SpAuthError>()));
      await until(() => events.whereType<SessionEnded>().isNotEmpty);

      expect(await store.read(), isNull);
      expect(auth.state, isA<Anonymous>());
      expect(events.whereType<SessionEnded>().length, equals(1));
    },
  );

  test(
    'HTTP 200 with success: false and error_code: 10002 triggers definitive SessionEnded',
    () async {
      final initialSession = StoredSession(
        accessToken: 'old_at',
        refreshToken: 'bad_rt',
        expiresAt: DateTime.now().toUtc().subtract(const Duration(seconds: 10)),
      );
      await store.write(initialSession);

      responseHandler = (options) async {
        return Response<dynamic>(
          requestOptions: options,
          statusCode: 200,
          data: {
            'success': false,
            'error_code': 10002,
            'message': 'Token has been revoked',
          },
        );
      };

      final auth = SpJwtAuth(
        baseUrl: Uri.parse('https://api.example.com'),
        endpoints: createEndpoints(),
        store: store,
        dio: mockDio,
      );
      await auth.restore();

      final events = <AuthEvent>[];
      auth.events.listen(events.add);

      await expectLater(auth.accessToken(), throwsA(isA<SpAuthError>()));
      await until(() => events.whereType<SessionEnded>().isNotEmpty);

      expect(await store.read(), isNull);
      expect(auth.state, isA<Anonymous>());
      expect(events.whereType<SessionEnded>().length, equals(1));
    },
  );

  test('network timeout is transient and preserves stored tokens', () async {
    final initialSession = StoredSession(
      accessToken: 'old_at',
      refreshToken: 'valid_rt',
      expiresAt: DateTime.now().toUtc().subtract(const Duration(seconds: 10)),
    );
    await store.write(initialSession);

    responseHandler = (options) async {
      throw DioException(
        requestOptions: options,
        type: DioExceptionType.connectionTimeout,
        message: 'Connection timed out',
      );
    };

    final auth = SpJwtAuth(
      baseUrl: Uri.parse('https://api.example.com'),
      endpoints: createEndpoints(),
      store: store,
      dio: mockDio,
    );
    await auth.restore();

    final events = <AuthEvent>[];
    auth.events.listen(events.add);

    await expectLater(
      auth.accessToken(),
      throwsA(
        isA<SpAuthError>().having(
          (e) => e.code,
          'code',
          SpAuthErrorCode.timeout,
        ),
      ),
    );
    // The failure was awaited above; give a (wrongly) emitted SessionEnded
    // one 10 ms window to show up before asserting that none did.
    await Future<void>.delayed(const Duration(milliseconds: 10));

    // Stored tokens MUST be preserved on transient errors!
    final preserved = await store.read();
    expect(preserved?.accessToken, equals('old_at'));
    expect(events.whereType<SessionEnded>(), isEmpty);
  });

  test(
    're-reading store under RefreshLock uses token rotated by another caller/isolate',
    () async {
      final initialSession = StoredSession(
        accessToken: 'old_at',
        refreshToken: 'valid_rt',
        expiresAt: DateTime.now().toUtc().subtract(const Duration(seconds: 10)),
      );
      await store.write(initialSession);

      var refreshCallCount = 0;
      responseHandler = (options) async {
        refreshCallCount++;
        return Response<dynamic>(
          requestOptions: options,
          statusCode: 200,
          data: {
            'success': true,
            'data': {
              'access_token': 'network_at',
              'refresh_token': 'network_rt',
              'expires_at':
                  DateTime.now()
                      .toUtc()
                      .add(const Duration(hours: 1))
                      .millisecondsSinceEpoch ~/
                  1000,
            },
          },
        );
      };

      final auth = SpJwtAuth(
        baseUrl: Uri.parse('https://api.example.com'),
        endpoints: createEndpoints(),
        store: store,
        dio: mockDio,
      );
      await auth.restore();

      // Another isolate writes new session to store
      await store.write(
        StoredSession(
          accessToken: 'already_rotated_at',
          refreshToken: 'already_rotated_rt',
          expiresAt: DateTime.now().toUtc().add(const Duration(hours: 1)),
        ),
      );

      final token = await auth.accessToken();
      expect(token, equals('already_rotated_at'));
      expect(refreshCallCount, equals(0)); // Zero HTTP calls made
    },
  );

  test(
    'headers() returns Authorization bearer when token is available',
    () async {
      final session = StoredSession(
        accessToken: 'my_secret_token',
        expiresAt: DateTime.now().toUtc().add(const Duration(hours: 1)),
      );
      await store.write(session);

      final auth = SpJwtAuth(
        baseUrl: Uri.parse('https://api.example.com'),
        endpoints: createEndpoints(),
        store: store,
        dio: mockDio,
      );

      final hdrs = await auth.headers();
      expect(hdrs, equals({'Authorization': 'Bearer my_secret_token'}));
    },
  );

  test(
    'handleUnauthorized() refreshes session and returns true on success',
    () async {
      final session = StoredSession(
        accessToken: 'stale_token',
        refreshToken: 'valid_refresh',
        expiresAt: DateTime.now().toUtc().subtract(const Duration(seconds: 5)),
      );
      await store.write(session);

      responseHandler = (options) async {
        return Response<dynamic>(
          requestOptions: options,
          statusCode: 200,
          data: {
            'success': true,
            'data': {
              'access_token': 'refreshed_access',
              'refresh_token': 'refreshed_refresh',
              'expires_at':
                  DateTime.now()
                      .toUtc()
                      .add(const Duration(hours: 1))
                      .millisecondsSinceEpoch ~/
                  1000,
            },
          },
        );
      };

      final auth = SpJwtAuth(
        baseUrl: Uri.parse('https://api.example.com'),
        endpoints: createEndpoints(),
        store: store,
        dio: mockDio,
      );
      await auth.restore();

      final success = await auth.handleUnauthorized();
      expect(success, isTrue);
      expect(await auth.accessToken(), equals('refreshed_access'));
    },
  );
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
      final String jsonStr;
      if (data is String) {
        jsonStr = data;
      } else {
        jsonStr = jsonEncode(data);
      }
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
