import 'dart:async';
import 'dart:convert';
import 'package:dio/dio.dart';
import 'package:sp_jwt_auth/sp_jwt_auth.dart';
import 'package:sp_jwt_auth/web.dart';
import 'package:test/test.dart';

void main() {
  late MemoryTokenStore store;
  late Dio mockDio;
  late List<RequestOptions> capturedRequests;
  late Future<Response<dynamic>> Function(RequestOptions options)
  responseHandler;
  late MockBrowserCookieEnv mockEnv;

  setUp(() {
    store = MemoryTokenStore();
    capturedRequests = [];
    mockEnv = MockBrowserCookieEnv();
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
          refreshToken: null, // httpOnly cookie holds refresh token
          expiresAt: DateTime.fromMillisecondsSinceEpoch(
            (map['expires_at'] as int) * 1000,
            isUtc: true,
          ),
          user: map['user'] as Map<String, dynamic>?,
        );
      },
    );
  }

  test(
    'Transport.cookie throws UnsupportedError on non-web VM when environment is missing',
    () {
      expect(
        () => SpJwtAuth(
          baseUrl: Uri.parse('https://api.example.com'),
          endpoints: createEndpoints(),
          store: store,
          transport: Transport.cookie,
          // no cookieEnv supplied
        ),
        throwsA(isA<UnsupportedError>()),
      );
    },
  );

  test(
    'cookie mode sends withCredentials and no body token on refresh',
    () async {
      final auth = SpJwtAuth(
        baseUrl: Uri.parse('https://api.example.com'),
        endpoints: createEndpoints(),
        store: store,
        dio: mockDio,
        transport: Transport.cookie,
        cookieEnv: mockEnv,
      );

      responseHandler = (options) async {
        if (options.path.contains('/auth/refresh')) {
          return Response<dynamic>(
            requestOptions: options,
            statusCode: 200,
            headers: Headers.fromMap({
              'X-SP-CSRF': ['csrf_token_from_header_123'],
            }),
            data: {
              'success': true,
              'data': {
                'access_token': 'cookie_access_token',
                'expires_at':
                    DateTime.now()
                        .toUtc()
                        .add(const Duration(hours: 1))
                        .millisecondsSinceEpoch ~/
                    1000,
                'user': {'id': 99},
              },
            },
          );
        }
        return Response<dynamic>(requestOptions: options, statusCode: 404);
      };

      final token = await auth.accessToken();
      expect(token, equals('cookie_access_token'));
      expect(capturedRequests.length, equals(1));
      final req = capturedRequests.first;

      // Must send withCredentials
      expect(req.extra['withCredentials'], isTrue);
      // Must NOT send body refresh token
      expect(req.data, isNull);
    },
  );

  test(
    'X-SP-CSRF is captured from response header and echoed on subsequent requests',
    () async {
      final auth = SpJwtAuth(
        baseUrl: Uri.parse('https://api.example.com'),
        endpoints: createEndpoints(),
        store: store,
        dio: mockDio,
        transport: Transport.cookie,
        cookieEnv: mockEnv,
      );

      responseHandler = (options) async {
        if (options.path.contains('/auth/refresh')) {
          return Response<dynamic>(
            requestOptions: options,
            statusCode: 200,
            headers: Headers.fromMap({
              'X-SP-CSRF': ['csrf_secret_abc'],
            }),
            data: {
              'success': true,
              'data': {
                'access_token': 'initial_access_token',
                'expires_at':
                    DateTime.now()
                        .toUtc()
                        .subtract(const Duration(seconds: 10))
                        .millisecondsSinceEpoch ~/
                    1000,
              },
            },
          );
        }
        return Response<dynamic>(requestOptions: options, statusCode: 404);
      };

      // First refresh sets the CSRF token
      await auth.accessToken();

      // Trigger second refresh
      responseHandler = (options) async {
        return Response<dynamic>(
          requestOptions: options,
          statusCode: 200,
          headers: Headers.fromMap({
            'X-SP-CSRF': ['csrf_secret_abc'],
          }),
          data: {
            'success': true,
            'data': {
              'access_token': 'second_access_token',
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

      await auth.accessToken();
      expect(capturedRequests.length, equals(2));
      final secondReq = capturedRequests[1];
      expect(secondReq.headers['X-SP-CSRF'], equals('csrf_secret_abc'));
    },
  );

  test(
    'HTTP 403 csrf_failed retries once after re-reading live cookie',
    () async {
      mockEnv.setCookie('sp_csrf', 'initial_bad_csrf');

      final auth = SpJwtAuth(
        baseUrl: Uri.parse('https://api.example.com'),
        endpoints: createEndpoints(),
        store: store,
        dio: mockDio,
        transport: Transport.cookie,
        cookieEnv: mockEnv,
      );

      var refreshAttempts = 0;
      responseHandler = (options) async {
        refreshAttempts++;
        if (refreshAttempts == 1) {
          // Update cookie in environment to simulate refreshed cookie
          mockEnv.setCookie('sp_csrf', 'live_updated_csrf');
          throw DioException(
            requestOptions: options,
            response: Response<dynamic>(
              requestOptions: options,
              statusCode: 403,
              data: {'code': 'csrf_failed', 'message': 'CSRF token mismatch'},
            ),
            type: DioExceptionType.badResponse,
          );
        }
        return Response<dynamic>(
          requestOptions: options,
          statusCode: 200,
          headers: Headers.fromMap({
            'X-SP-CSRF': ['live_updated_csrf'],
          }),
          data: {
            'success': true,
            'data': {
              'access_token': 'csrf_recovered_token',
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

      final token = await auth.accessToken();
      expect(token, equals('csrf_recovered_token'));
      expect(refreshAttempts, equals(2));
      expect(
        capturedRequests[1].headers['X-SP-CSRF'],
        equals('live_updated_csrf'),
      );
    },
  );

  test(
    'the CSRF retry in the refresh engine is logged as attempt 1 then attempt 2',
    () async {
      mockEnv.setCookie('sp_csrf', 'initial_bad_csrf');
      final entries = <AuthLogEntry>[];
      final auth = SpJwtAuth(
        baseUrl: Uri.parse('https://api.example.com'),
        endpoints: createEndpoints(),
        store: store,
        dio: mockDio,
        transport: Transport.cookie,
        cookieEnv: mockEnv,
        logger: AuthLogger(sink: entries.add),
        logRequests: true,
      );

      var refreshAttempts = 0;
      responseHandler = (options) async {
        refreshAttempts++;
        if (refreshAttempts == 1) {
          mockEnv.setCookie('sp_csrf', 'live_updated_csrf');
          throw DioException(
            requestOptions: options,
            response: Response<dynamic>(
              requestOptions: options,
              statusCode: 403,
              data: {'code': 'csrf_failed', 'message': 'CSRF token mismatch'},
            ),
            type: DioExceptionType.badResponse,
          );
        }
        return Response<dynamic>(
          requestOptions: options,
          statusCode: 200,
          data: {
            'success': true,
            'data': {
              'access_token': 'csrf_recovered_token',
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

      expect(await auth.accessToken(), equals('csrf_recovered_token'));
      expect(
        entries.map((e) => (e.method, e.path, e.status, e.attempt)).toList(),
        [('POST', '/auth/refresh', 403, 1), ('POST', '/auth/refresh', 200, 2)],
      );
      expect(entries.first.code, isNotNull);
      expect(entries.last.code, isNull);
    },
  );

  test(
    'broadcastGraceMs defaults to 100ms on cookie transport configuration',
    () {
      const config = CookieTransportConfig();
      expect(config.broadcastGraceMs, equals(100));
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
      final headersMap = <String, List<String>>{
        Headers.contentTypeHeader: [Headers.jsonContentType],
      };
      res.headers.map.forEach((k, v) {
        headersMap[k] = v;
      });
      return ResponseBody.fromString(
        jsonStr,
        res.statusCode ?? 200,
        headers: headersMap,
      );
    } on DioException catch (e) {
      if (e.response != null) {
        final d = e.response?.data;
        final jsonStr = d is String ? d : jsonEncode(d);
        final headersMap = <String, List<String>>{
          Headers.contentTypeHeader: [Headers.jsonContentType],
        };
        e.response?.headers.map.forEach((k, v) {
          headersMap[k] = v;
        });
        return ResponseBody.fromString(
          jsonStr,
          e.response?.statusCode ?? 500,
          headers: headersMap,
        );
      }
      rethrow;
    }
  }

  @override
  void close({bool force = false}) {}
}
