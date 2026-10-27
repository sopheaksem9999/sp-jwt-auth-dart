import 'dart:convert';
import 'package:dio/dio.dart';
import 'package:sp_jwt_auth/account.dart';
import 'package:sp_jwt_auth/mfa.dart';
import 'package:sp_jwt_auth/otp.dart';
import 'package:sp_jwt_auth/sessions.dart';
import 'package:sp_jwt_auth/sp_jwt_auth.dart';
import 'package:sp_jwt_auth/src/url.dart';
import 'package:test/test.dart';

class _CaptureAdapter implements HttpClientAdapter {
  final List<RequestOptions> requests = [];

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<List<int>>? requestStream,
    Future<void>? cancelFuture,
  ) async {
    requests.add(options);
    return ResponseBody.fromString(
      jsonEncode({
        'success': true,
        'data': {
          'access_token': 'a',
          'refresh_token': 'r',
          'expires_in': 3600,
          'user': {'id': 1},
        },
      }),
      200,
      headers: {
        Headers.contentTypeHeader: [Headers.jsonContentType],
      },
    );
  }

  @override
  void close({bool force = false}) {}
}

SpJwtAuth _auth(
  String base, {
  bool? relative,
  _CaptureAdapter? adapter,
  TokenStore? store,
}) {
  final dio = Dio();
  if (adapter != null) dio.httpClientAdapter = adapter;
  return SpJwtAuth(
    baseUrl: Uri.parse(base),
    endpoints: relative == null
        ? const Endpoints()
        : Endpoints(relativeToBase: relative),
    store: store ?? MemoryTokenStore(),
    dio: dio,
  );
}

void main() {
  group('resolveEndpoint', () {
    final b = Uri.parse('https://h/api/v1');
    test('relative joins under base path', () {
      expect(
        resolveEndpoint(b, '/rpc/auth/refresh', relativeToBase: true),
        Uri.parse('https://h/api/v1/rpc/auth/refresh'),
      );
    });
    test('default (absolute) replaces base path', () {
      expect(
        resolveEndpoint(b, '/rpc/auth/refresh', relativeToBase: false),
        Uri.parse('https://h/rpc/auth/refresh'),
      );
    });
    test('base without path is identical in both modes', () {
      final h = Uri.parse('https://h');
      expect(
        resolveEndpoint(h, '/auth/login', relativeToBase: true),
        resolveEndpoint(h, '/auth/login', relativeToBase: false),
      );
      expect(
        resolveEndpoint(h, '/auth/login', relativeToBase: true),
        Uri.parse('https://h/auth/login'),
      );
    });
    test('trailing slash and missing leading slash yield single slash', () {
      final expected = Uri.parse('https://h/api/v1/auth/login');
      for (final base in ['https://h/api/v1/', 'https://h/api/v1']) {
        for (final path in ['/auth/login', 'auth/login']) {
          expect(
            resolveEndpoint(Uri.parse(base), path, relativeToBase: true),
            expected,
            reason: '$base + $path',
          );
        }
      }
    });
  });

  group('Endpoints.relativeToBase', () {
    test('defaults to false', () {
      expect(const Endpoints().relativeToBase, isFalse);
    });
  });

  group('SpJwtAuth.endpointUri', () {
    const paths = [
      '/auth/login',
      '/auth/refresh',
      '/auth/logout',
      '/auth/whoami',
      '/auth/otp/send',
      '/auth/mfa/methods',
      '/auth/account/profile',
      '/auth/sessions',
    ];
    for (final p in paths) {
      test('relative: $p', () {
        expect(
          _auth('https://h/api/v1', relative: true).endpointUri(p),
          Uri.parse('https://h/api/v1$p'),
        );
      });
      test('absolute default: $p', () {
        expect(
          _auth('https://h/api/v1').endpointUri(p),
          Uri.parse('https://h$p'),
        );
      });
    }
  });

  group('end-to-end requested URLs (relativeToBase: true)', () {
    late _CaptureAdapter adapter;
    late MemoryTokenStore store;
    late SpJwtAuth auth;

    setUp(() {
      adapter = _CaptureAdapter();
      store = MemoryTokenStore();
      auth = _auth(
        'https://h/api/v1',
        relative: true,
        adapter: adapter,
        store: store,
      );
    });

    Future<void> expectUrl(Future<void> Function() call, String url) async {
      adapter.requests.clear();
      try {
        await call();
      } catch (_) {}
      expect(adapter.requests, isNotEmpty);
      expect(
        adapter.requests.first.uri.removeFragment().toString().split('?').first,
        url,
      );
    }

    test('login', () async {
      await expectUrl(
        () => auth.login({'email': 'a@example.com', 'password': 'x'}),
        'https://h/api/v1/auth/login',
      );
    });
    test('whoami', () async {
      await auth.login({'email': 'a@example.com', 'password': 'x'});
      await expectUrl(() => auth.whoami(), 'https://h/api/v1/auth/whoami');
    });
    test('refresh', () async {
      await auth.login({'email': 'a@example.com', 'password': 'x'});
      await expectUrl(
        () => auth.handleUnauthorized(),
        'https://h/api/v1/auth/refresh',
      );
    });
    test('logout', () async {
      await auth.login({'email': 'a@example.com', 'password': 'x'});
      await expectUrl(() => auth.logout(), 'https://h/api/v1/auth/logout');
    });
    test('otp send', () async {
      await expectUrl(
        () => OtpModule(auth).sendOtp(identifier: 'a', channel: 'email'),
        'https://h/api/v1/auth/otp/send',
      );
    });
    test('mfa methods', () async {
      await expectUrl(
        () => MfaModule(auth).listMethods(challengeId: 'c'),
        'https://h/api/v1/auth/mfa/methods',
      );
    });
    test('account change-password', () async {
      await expectUrl(
        () => AccountModule(
          auth,
        ).changePassword(currentPassword: 'a', newPassword: 'b'),
        'https://h/api/v1/auth/account/change-password',
      );
    });
    test('sessions list', () async {
      await expectUrl(
        () => SessionsModule(auth).list(),
        'https://h/api/v1/auth/sessions',
      );
    });
    test('sessions revoke interpolated id', () async {
      await expectUrl(
        () => SessionsModule(auth).revoke('abc'),
        'https://h/api/v1/auth/sessions/abc',
      );
    });
  });
}
