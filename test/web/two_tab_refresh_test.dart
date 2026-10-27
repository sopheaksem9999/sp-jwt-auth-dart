import 'dart:async';
import 'dart:convert';
import 'package:dio/dio.dart';
import 'package:sp_jwt_auth/sp_jwt_auth.dart';
import 'package:sp_jwt_auth/web.dart';
import 'package:test/test.dart';

void main() {
  group('Two-Tab Concurrent Refresh Simulation (Web Locks + TabSync)', () {
    late MemoryTokenStore sharedStore;
    late List<RequestOptions> capturedNetworkRequests;
    late WebLocksRefreshLock sharedLock;

    setUp(() {
      sharedStore = MemoryTokenStore();
      capturedNetworkRequests = [];
      sharedLock = WebLocksRefreshLock();
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

    Dio createMockDio() {
      final dio = Dio(BaseOptions(baseUrl: 'https://api.example.com'));
      dio.httpClientAdapter = _MockHttpAdapter((options) async {
        capturedNetworkRequests.add(options);

        if (options.path.endsWith('/auth/refresh')) {
          await Future<void>.delayed(const Duration(milliseconds: 25));
          final futureExp = DateTime.now().toUtc().add(
            const Duration(hours: 1),
          );
          return Response(
            requestOptions: options,
            statusCode: 200,
            data: {
              'data': {
                'access_token': 'new_rotated_at_123',
                'refresh_token': 'new_rotated_rt_456',
                'expires_at': futureExp.millisecondsSinceEpoch ~/ 1000,
                'user': {'id': 1, 'email': 'user@example.com'},
              },
            },
          );
        }

        return Response(
          requestOptions: options,
          statusCode: 200,
          data: <String, dynamic>{},
        );
      });
      return dio;
    }

    test(
      'two simultaneous tab refresh calls trigger exactly ONE network request',
      () async {
        // Seed shared store with an expiring session
        final expiringSession = StoredSession(
          accessToken: 'old_expiring_at',
          refreshToken: 'valid_refresh_token',
          expiresAt: DateTime.now().toUtc().add(const Duration(seconds: 10)),
        );
        await sharedStore.write(expiringSession);

        final tab1Sync = TabSync(channel: MockBroadcastChannel('tab-channel'));
        final tab2Sync = TabSync(channel: MockBroadcastChannel('tab-channel'));

        final tab1Auth = SpJwtAuth(
          baseUrl: Uri.parse('https://api.example.com'),
          endpoints: createEndpoints(),
          store: sharedStore,
          refreshLock: sharedLock,
          dio: createMockDio(),
        );

        final tab2Auth = SpJwtAuth(
          baseUrl: Uri.parse('https://api.example.com'),
          endpoints: createEndpoints(),
          store: sharedStore,
          refreshLock: sharedLock,
          dio: createMockDio(),
        );

        await tab1Auth.restore();
        await tab2Auth.restore();

        // Drive both instances to trigger proactive refresh concurrently
        final results = await Future.wait<String?>([
          tab1Auth.accessToken(),
          tab2Auth.accessToken(),
        ]);

        // Exactly ONE network refresh request was fired
        expect(capturedNetworkRequests.length, equals(1));
        expect(capturedNetworkRequests.first.path, endsWith('/auth/refresh'));

        // Both tabs received the fresh rotated token
        expect(results[0], equals('new_rotated_at_123'));
        expect(results[1], equals('new_rotated_at_123'));

        // Both tab instances are authenticated with the same session
        expect(tab1Auth.state, isA<Authenticated>());
        expect(tab2Auth.state, isA<Authenticated>());

        tab1Sync.dispose();
        tab2Sync.dispose();
        tab1Auth.dispose();
        tab2Auth.dispose();
      },
    );
  });
}

class _MockHttpAdapter implements HttpClientAdapter {
  final Future<Response<dynamic>> Function(RequestOptions options) handler;

  _MockHttpAdapter(this.handler);

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<List<int>>? requestStream,
    Future<void>? cancelFuture,
  ) async {
    final res = await handler(options);
    final data = res.data;
    final jsonStr = data is String ? data : jsonEncode(data);
    return ResponseBody.fromString(
      jsonStr,
      res.statusCode ?? 200,
      headers: {
        Headers.contentTypeHeader: [Headers.jsonContentType],
      },
    );
  }

  @override
  void close({bool force = false}) {}
}
