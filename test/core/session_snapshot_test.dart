import 'dart:async';
import 'dart:convert';
import 'package:dio/dio.dart';
import 'package:sp_jwt_auth/sp_jwt_auth.dart';
import 'package:sp_jwt_auth/web.dart';
import 'package:test/test.dart';

String _jwt(String sub) {
  String b(Object o) =>
      base64Url.encode(utf8.encode(jsonEncode(o))).replaceAll('=', '');
  return '${b({'alg': 'none'})}.${b({'sub': sub})}.sig';
}

void main() {
  late MemoryTokenStore store;
  late SpJwtAuth auth;
  late int requests;
  late Future<Response<dynamic>> Function(RequestOptions) handler;

  Map<String, dynamic> body(String at, {String rt = 'rt2'}) => {
    'success': true,
    'data': {
      'access_token': at,
      'refresh_token': rt,
      'expires_in': 3600,
      'user': {'id': 7},
    },
  };

  setUp(() {
    requests = 0;
    store = MemoryTokenStore();
    final dio = Dio(BaseOptions(baseUrl: 'https://api.example.com'));
    dio.httpClientAdapter = _Adapter((o) async {
      requests++;
      return handler(o);
    });
    auth = SpJwtAuth(
      baseUrl: Uri.parse('https://api.example.com'),
      endpoints: Endpoints(
        login: '/auth/login',
        refresh: '/auth/refresh',
        logout: '/auth/logout',
        whoami: '/auth/whoami',
      ),
      store: store,
      dio: dio,
    );
  });

  StoredSession expired() => StoredSession(
    accessToken: 'old',
    refreshToken: 'rt1',
    expiresAt: DateTime.now().toUtc().subtract(const Duration(minutes: 1)),
  );

  test('currentSession non-null after restore, null after logout', () async {
    expect(auth.currentSession, isNull);
    expect(auth.isAuthenticated, isFalse);
    await store.write(
      StoredSession(accessToken: _jwt('u1'), refreshToken: 'r'),
    );
    await auth.restore();
    expect(auth.currentSession, isNotNull);
    expect(auth.isAuthenticated, isTrue);
    expect(auth.userId, 'u1');
    handler = (o) async =>
        Response(requestOptions: o, data: <String, dynamic>{});
    await auth.logout();
    expect(auth.currentSession, isNull);
    expect(auth.isAuthenticated, isFalse);
    expect(auth.userId, isNull);
    expect(auth.accessTokenSync, isNull);
  });

  test('userId prefers user id over sub', () async {
    await store.write(
      StoredSession(accessToken: _jwt('sub1'), user: {'id': 42}),
    );
    await auth.restore();
    expect(auth.userId, '42');
  });

  test('currentSession reflects background refresh inside listener', () async {
    await store.write(expired());
    await auth.restore();
    handler = (o) async => Response(requestOptions: o, data: body('new'));
    String? seen;
    auth.addListener(() => seen = auth.currentSession?.accessToken);
    await auth.accessToken();
    expect(seen, 'new');
    expect(auth.accessTokenSync, 'new');
  });

  test('listener is not called after dispose', () async {
    var n = 0;
    auth.addListener(() => n++);
    await auth.dispose();
    handler = (o) async => Response(requestOptions: o, data: body('a'));
    try {
      await auth.login({'u': 'x'});
    } catch (_) {}
    expect(n, 0);
  });

  test(
    'listener fires on login, refresh, logout and rejected refresh',
    () async {
      var n = 0;
      auth.addListener(() => n++);
      handler = (o) async => Response(requestOptions: o, data: body('a'));
      await auth.login({'u': 'x'});
      expect(n, 1);

      await store.write(expired());
      await auth.restore();
      n = 0;
      await auth.accessToken();
      expect(n, 1);

      handler = (o) async =>
          Response(requestOptions: o, data: <String, dynamic>{});
      await auth.logout();
      expect(n, 2);

      await store.write(expired());
      await auth.restore();
      n = 0;
      handler = (o) async => Response(
        requestOptions: o,
        data: {'success': false, 'message': 'revoked', 'error_code': 10010},
      );
      await expectLater(auth.accessToken(), throwsA(isA<SpAuthError>()));
      expect(n, 1);
      expect(auth.currentSession, isNull);
    },
  );

  test('accessTokenSync never starts a request', () async {
    await store.write(expired());
    await auth.restore();
    final before = requests;
    expect(auth.accessTokenSync, 'old');
    expect(requests, before);
  });

  test('snapshot never lags state after Refreshed', () async {
    await store.write(expired());
    await auth.restore();
    handler = (o) async => Response(requestOptions: o, data: body('fresh'));
    final seen = Completer<String?>();
    final sub = auth.events.listen((e) {
      if (e is Refreshed) seen.complete(auth.currentSession!.accessToken);
    });
    await auth.accessToken();
    expect(await seen.future, 'fresh');
    await sub.cancel();
  });

  test('throwing listener does not stop others', () async {
    var second = 0;
    auth.addListener(() => throw StateError('boom'));
    auth.addListener(() => second++);
    handler = (o) async => Response(requestOptions: o, data: body('a'));
    await auth.login({});
    expect(second, 1);
    expect(auth.isAuthenticated, isTrue);
  });

  test('listener removing itself during dispatch is safe', () async {
    var a = 0, b = 0;
    late void Function() removeA;
    removeA = auth.addListener(() {
      a++;
      removeA();
    });
    auth.addListener(() => b++);
    handler = (o) async => Response(requestOptions: o, data: body('a'));
    await auth.login({});
    await auth.login({});
    expect(a, 1);
    expect(b, 2);
  });

  test('cross-tab messages update snapshot then notify', () async {
    final other = MockBroadcastChannel('snap-test');
    final tab = TabSync(channelName: 'snap-test');
    final a2 = SpJwtAuth(
      baseUrl: Uri.parse('https://api.example.com'),
      endpoints: Endpoints(
        login: '/l',
        refresh: '/r',
        logout: '/o',
        whoami: '/w',
      ),
      store: MemoryTokenStore(),
      tabSync: tab,
    );
    final seen = <String?>[];
    a2.addListener(() => seen.add(a2.accessTokenSync));
    other.postMessage({
      'type': 'refreshed',
      'session': StoredSession(accessToken: 'x').toJson(),
    });
    await Future<void>.delayed(Duration.zero);
    other.postMessage({'type': 'logged_out'});
    await Future<void>.delayed(Duration.zero);
    expect(seen, ['x', null]);
    await a2.dispose();
    tab.dispose();
    other.close();
  });
}

class _Adapter implements HttpClientAdapter {
  final Future<Response<dynamic>> Function(RequestOptions) h;
  _Adapter(this.h);
  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<List<int>>? requestStream,
    Future<void>? cancelFuture,
  ) async {
    final res = await h(options);
    return ResponseBody.fromString(
      jsonEncode(res.data),
      res.statusCode ?? 200,
      headers: {
        Headers.contentTypeHeader: [Headers.jsonContentType],
      },
    );
  }

  @override
  void close({bool force = false}) {}
}
