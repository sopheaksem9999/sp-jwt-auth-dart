import 'dart:async';
import 'dart:convert';
import 'package:dio/dio.dart';
import 'package:sp_jwt_auth/account.dart';
import 'package:sp_jwt_auth/mfa.dart';
import 'package:sp_jwt_auth/otp.dart';
import 'package:sp_jwt_auth/sessions.dart';
import 'package:sp_jwt_auth/sp_jwt_auth.dart';
import 'package:test/test.dart';

void main() {
  late MemoryTokenStore store;
  late Dio mockDio;
  late List<RequestOptions> capturedRequests;
  late Future<Response<dynamic>> Function(RequestOptions options)
  responseHandler;
  late SpJwtAuth auth;

  setUp(() {
    store = MemoryTokenStore();
    capturedRequests = [];
    mockDio = Dio(BaseOptions(baseUrl: 'https://api.example.com'));
    mockDio.httpClientAdapter = _MockAdapter((options) async {
      capturedRequests.add(options);
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
    );
  });

  group('OtpModule', () {
    test(
      'sendOtp posts to /auth/otp/send with identifier and channel',
      () async {
        final otp = OtpModule(auth);
        responseHandler = (options) async {
          return Response<dynamic>(
            requestOptions: options,
            statusCode: 200,
            data: {'success': true, 'message': 'OTP sent'},
          );
        };

        await otp.sendOtp(identifier: 'user@example.com', channel: 'email');
        expect(capturedRequests.length, equals(1));
        final req = capturedRequests.first;
        expect(req.path, contains('/auth/otp/send'));
        expect(
          req.data,
          equals({'identifier': 'user@example.com', 'channel': 'email'}),
        );
      },
    );

    test(
      'verifyOtp posts to /auth/otp/verify and stores session on success',
      () async {
        final otp = OtpModule(auth);
        responseHandler = (options) async {
          return Response<dynamic>(
            requestOptions: options,
            statusCode: 200,
            data: {
              'success': true,
              'data': {
                'access_token': 'otp_verified_token',
                'refresh_token': 'otp_rt',
                'expires_at':
                    DateTime.now()
                        .toUtc()
                        .add(const Duration(hours: 1))
                        .millisecondsSinceEpoch ~/
                    1000,
                'user': {'id': 7},
              },
            },
          );
        };

        final result = await otp.verifyOtp(
          identifier: 'user@example.com',
          code: '123456',
        );
        expect(result, isA<AuthenticatedResult>());
        expect(await auth.accessToken(), equals('otp_verified_token'));
      },
    );
  });

  group('MfaModule', () {
    test('listMethods queries /auth/mfa/methods with challengeId', () async {
      final mfa = MfaModule(auth);
      responseHandler = (options) async {
        return Response<dynamic>(
          requestOptions: options,
          statusCode: 200,
          data: {
            'success': true,
            'data': ['totp', 'sms'],
          },
        );
      };

      final methods = await mfa.listMethods(challengeId: 'ch_456');
      expect(methods, equals(['totp', 'sms']));
      expect(
        capturedRequests.first.queryParameters['challenge_id'],
        equals('ch_456'),
      );
    });

    test('verify completes MFA and returns AuthenticatedResult', () async {
      final mfa = MfaModule(auth);
      responseHandler = (options) async {
        return Response<dynamic>(
          requestOptions: options,
          statusCode: 200,
          data: {
            'success': true,
            'data': {
              'access_token': 'mfa_authenticated_token',
              'refresh_token': 'mfa_rt',
              'expires_at':
                  DateTime.now()
                      .toUtc()
                      .add(const Duration(hours: 1))
                      .millisecondsSinceEpoch ~/
                  1000,
              'user': {'id': 10},
            },
          },
        );
      };

      final res = await mfa.verify(challengeId: 'ch_456', code: '654321');
      expect(res, isA<AuthenticatedResult>());
      expect(await auth.accessToken(), equals('mfa_authenticated_token'));
    });
  });

  group('SessionsModule', () {
    test('list queries /auth/sessions with auth headers', () async {
      await store.write(
        StoredSession(
          accessToken: 'sess_token',
          expiresAt: DateTime.now().toUtc().add(const Duration(hours: 1)),
        ),
      );
      await auth.restore();

      final sessions = SessionsModule(auth);
      responseHandler = (options) async {
        return Response<dynamic>(
          requestOptions: options,
          statusCode: 200,
          data: {
            'data': [
              {'id': 's1', 'current': true, 'ip': '127.0.0.1'},
              {'id': 's2', 'current': false, 'ip': '10.0.0.1'},
            ],
          },
        );
      };

      final list = await sessions.list();
      expect(list.length, equals(2));
      expect(
        capturedRequests.first.headers['Authorization'],
        equals('Bearer sess_token'),
      );
    });

    test('revoke sends DELETE /auth/sessions/:id', () async {
      await store.write(
        StoredSession(
          accessToken: 'sess_token',
          expiresAt: DateTime.now().toUtc().add(const Duration(hours: 1)),
        ),
      );
      await auth.restore();

      final sessions = SessionsModule(auth);
      responseHandler = (options) async {
        return Response<dynamic>(
          requestOptions: options,
          statusCode: 200,
          data: {'success': true},
        );
      };

      await sessions.revoke('s2');
      expect(capturedRequests.first.method, equals('DELETE'));
      expect(capturedRequests.first.path, contains('/auth/sessions/s2'));
    });

    test('revokeOthers sends POST /auth/sessions/revoke-others', () async {
      await store.write(
        StoredSession(
          accessToken: 'sess_token',
          expiresAt: DateTime.now().toUtc().add(const Duration(hours: 1)),
        ),
      );
      await auth.restore();

      final sessions = SessionsModule(auth);
      responseHandler = (options) async {
        return Response<dynamic>(
          requestOptions: options,
          statusCode: 200,
          data: {'success': true},
        );
      };

      await sessions.revokeOthers();
      expect(capturedRequests.first.method, equals('POST'));
      expect(
        capturedRequests.first.path,
        contains('/auth/sessions/revoke-others'),
      );
    });
  });

  group('AccountModule', () {
    test('changePassword sends POST /auth/account/change-password', () async {
      await store.write(
        StoredSession(
          accessToken: 'account_token',
          expiresAt: DateTime.now().toUtc().add(const Duration(hours: 1)),
        ),
      );
      await auth.restore();

      final account = AccountModule(auth);
      responseHandler = (options) async {
        return Response<dynamic>(
          requestOptions: options,
          statusCode: 200,
          data: {'success': true},
        );
      };

      await account.changePassword(
        currentPassword: 'old_secret_pwd',
        newPassword: 'new_secret_pwd',
      );
      expect(
        capturedRequests.first.path,
        contains('/auth/account/change-password'),
      );
      expect(
        capturedRequests.first.data,
        equals({
          'current_password': 'old_secret_pwd',
          'new_password': 'new_secret_pwd',
        }),
      );
    });

    test('updateProfile sends PUT /auth/account/profile', () async {
      await store.write(
        StoredSession(
          accessToken: 'account_token',
          expiresAt: DateTime.now().toUtc().add(const Duration(hours: 1)),
        ),
      );
      await auth.restore();

      final account = AccountModule(auth);
      responseHandler = (options) async {
        return Response<dynamic>(
          requestOptions: options,
          statusCode: 200,
          data: {
            'data': {'id': 1, 'name': 'Updated Name'},
          },
        );
      };

      final updated = await account.updateProfile({'name': 'Updated Name'});
      expect(capturedRequests.first.method, equals('PUT'));
      expect(capturedRequests.first.path, contains('/auth/account/profile'));
      expect(updated['data']['name'], equals('Updated Name'));
    });
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
