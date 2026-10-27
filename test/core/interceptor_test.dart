import 'dart:async';
import 'dart:convert';
import 'package:dio/dio.dart';
import 'package:sp_jwt_auth/sp_jwt_auth.dart';
import 'package:test/test.dart';

void main() {
  late MemoryTokenStore store;
  late Dio authDio;
  late Dio clientDio;
  late List<RequestOptions> clientRequests;
  late SpJwtAuth auth;
  late Future<Response<dynamic>> Function(RequestOptions options) clientHandler;

  setUp(() {
    store = MemoryTokenStore();
    clientRequests = [];

    authDio = Dio(BaseOptions(baseUrl: 'https://api.example.com'));
    clientDio = Dio(BaseOptions(baseUrl: 'https://api.example.com'));

    clientDio.httpClientAdapter = _MockAdapter((options) async {
      clientRequests.add(options.copyWith());
      return clientHandler(options);
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
          );
        },
      ),
      store: store,
      dio: authDio,
    );
  });

  test('attach(Dio) adds Authorization header to outgoing requests', () async {
    await store.write(
      StoredSession(
        accessToken: 'valid_bearer_token',
        expiresAt: DateTime.now().toUtc().add(const Duration(hours: 1)),
      ),
    );
    await auth.restore();

    auth.attach(clientDio);

    clientHandler = (options) async {
      return Response<dynamic>(
        requestOptions: options,
        statusCode: 200,
        data: {'status': 'ok'},
      );
    };

    final res = await clientDio.get<dynamic>('/items');
    expect(res.statusCode, equals(200));
    expect(clientRequests.length, equals(1));
    expect(
      clientRequests.first.headers['Authorization'],
      equals('Bearer valid_bearer_token'),
    );
  });

  test(
    'interceptor catches 401 once, refreshes, and retries original request',
    () async {
      await store.write(
        StoredSession(
          accessToken: 'stale_token',
          refreshToken: 'valid_refresh_token',
          expiresAt: DateTime.now().toUtc().add(const Duration(minutes: 5)),
        ),
      );
      await auth.restore();

      // Mock authDio refresh response
      authDio.httpClientAdapter = _MockAdapter((options) async {
        if (options.path.contains('/auth/refresh')) {
          return Response<dynamic>(
            requestOptions: options,
            statusCode: 200,
            data: {
              'success': true,
              'data': {
                'access_token': 'fresh_new_token',
                'refresh_token': 'fresh_refresh_token',
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
      });

      auth.attach(clientDio);

      var callCount = 0;
      clientHandler = (options) async {
        callCount++;
        if (callCount == 1) {
          // First attempt fails with 401
          throw DioException(
            requestOptions: options,
            response: Response<dynamic>(
              requestOptions: options,
              statusCode: 401,
              data: {'message': 'Unauthenticated'},
            ),
            type: DioExceptionType.badResponse,
          );
        }
        // Retry succeeds
        return Response<dynamic>(
          requestOptions: options,
          statusCode: 200,
          data: {'retried': true},
        );
      };

      final res = await clientDio.get<dynamic>('/protected/resource');
      expect(res.statusCode, equals(200));
      expect(res.data, equals({'retried': true}));
      expect(callCount, equals(2));
      expect(clientRequests.length, equals(2));
      expect(
        clientRequests[0].headers['Authorization'],
        equals('Bearer stale_token'),
      );
      expect(
        clientRequests[1].headers['Authorization'],
        equals('Bearer fresh_new_token'),
      );
    },
  );

  test('requests with sp.authHandled = true are skipped on 401', () async {
    await store.write(
      StoredSession(
        accessToken: 'stale_token',
        refreshToken: 'valid_refresh_token',
        expiresAt: DateTime.now().toUtc().add(const Duration(minutes: 5)),
      ),
    );
    await auth.restore();

    auth.attach(clientDio);

    var callCount = 0;
    clientHandler = (options) async {
      callCount++;
      throw DioException(
        requestOptions: options,
        response: Response<dynamic>(
          requestOptions: options,
          statusCode: 401,
          data: {'message': 'Unauthenticated'},
        ),
        type: DioExceptionType.badResponse,
      );
    };

    await expectLater(
      clientDio.get<dynamic>(
        '/protected/resource',
        options: Options(extra: {'sp.authHandled': true}),
      ),
      throwsA(
        isA<DioException>().having(
          (e) => e.response?.statusCode,
          'status',
          401,
        ),
      ),
    );
    // Should NOT retry because sp.authHandled was true
    expect(callCount, equals(1));
  });

  test(
    'requests with skipAuth = true omit Authorization and do not retry on 401',
    () async {
      await store.write(
        StoredSession(
          accessToken: 'valid_token',
          expiresAt: DateTime.now().toUtc().add(const Duration(hours: 1)),
        ),
      );
      await auth.restore();

      auth.attach(clientDio);

      clientHandler = (options) async {
        return Response<dynamic>(
          requestOptions: options,
          statusCode: 200,
          data: {'public': true},
        );
      };

      await clientDio.get<dynamic>(
        '/public/endpoint',
        options: Options(extra: {'skipAuth': true}),
      );
      expect(clientRequests.first.headers['Authorization'], isNull);
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
