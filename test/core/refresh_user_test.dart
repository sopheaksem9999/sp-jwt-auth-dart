import 'dart:convert';
import 'package:dio/dio.dart';
import 'package:sp_jwt_auth/sp_jwt_auth.dart';
import 'package:test/test.dart';

class _MemStorage implements KeyValueStorage {
  final Map<String, String> data = {};
  @override
  Future<String?> read(String key) async => data[key];
  @override
  Future<void> write(String key, String value) async => data[key] = value;
  @override
  Future<void> delete(String key) async => data.remove(key);
}

class _Adapter implements HttpClientAdapter {
  final ResponseBody Function(RequestOptions options) handler;
  _Adapter(this.handler);

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<List<int>>? requestStream,
    Future<void>? cancelFuture,
  ) async => handler(options);

  @override
  void close({bool force = false}) {}
}

ResponseBody _json(Object body, [int status = 200]) => ResponseBody.fromString(
  jsonEncode(body),
  status,
  headers: {
    Headers.contentTypeHeader: [Headers.jsonContentType],
  },
);

void main() {
  late _MemStorage storage;
  late KeyValueTokenStore store;
  late int refreshCount;
  late ResponseBody Function(RequestOptions) refreshHandler;
  late Map<String, dynamic>? loginUser;

  Map<String, dynamic> tokens(
    String at,
    String rt, {
    Map<String, dynamic>? user,
  }) => {
    'success': true,
    'data': {
      'access_token': at,
      'refresh_token': rt,
      'token_type': 'Bearer',
      'expires_in': 10, // inside refreshAhead, so the next call refreshes
      if (user != null) 'user': user,
    },
  };

  SpJwtAuth makeAuth(KeyValueTokenStore s) {
    final dio = Dio(BaseOptions(baseUrl: 'https://api.example.com'));
    dio.httpClientAdapter = _Adapter((o) {
      if (o.path.contains('/auth/login')) {
        return _json(tokens('at_login', 'rt_login', user: loginUser));
      }
      if (o.path.contains('/auth/refresh')) {
        refreshCount++;
        return refreshHandler(o);
      }
      return _json({}, 404);
    });
    return SpJwtAuth(
      baseUrl: Uri.parse('https://api.example.com'),
      endpoints: Endpoints(
        login: '/auth/login',
        refresh: '/auth/refresh',
        logout: '/auth/logout',
        whoami: '/auth/whoami',
      ),
      store: s,
      dio: dio,
      refreshAhead: const Duration(seconds: 60),
    );
  }

  setUp(() {
    storage = _MemStorage();
    store = KeyValueTokenStore(storage);
    refreshCount = 0;
    loginUser = {'id': 7, 'name': 'Ada'};
    refreshHandler = (_) =>
        _json(tokens('at_$refreshCount', 'rt_$refreshCount'));
  });

  test('refresh without a user carries the login user', () async {
    final auth = makeAuth(store);
    await auth.login({'email': 'a@example.com', 'password': 'x'});
    final events = <AuthEvent>[];
    auth.events.listen(events.add);

    final token = await auth.accessToken();

    expect(token, 'at_1');
    expect(auth.currentSession!.accessToken, 'at_1');
    expect(auth.currentSession!.user, {'id': 7, 'name': 'Ada'});
    await Future<void>.delayed(Duration.zero);
    final refreshed = events.whereType<Refreshed>().single;
    expect(refreshed.session.user, {'id': 7, 'name': 'Ada'});
  });

  test('stored user survives refresh and a restart restores it', () async {
    final auth = makeAuth(store);
    await auth.login({'email': 'a@example.com', 'password': 'x'});
    await auth.accessToken();

    expect((await store.read())!.user, {'id': 7, 'name': 'Ada'});

    final restarted = makeAuth(KeyValueTokenStore(storage));
    await restarted.restore();
    expect(restarted.currentSession!.accessToken, 'at_1');
    expect(restarted.currentSession!.user, {'id': 7, 'name': 'Ada'});
  });

  test('a user in the refresh response replaces the old one', () async {
    refreshHandler = (_) =>
        _json(tokens('at_new', 'rt_new', user: {'id': 7, 'name': 'Grace'}));
    final auth = makeAuth(store);
    await auth.login({'email': 'a@example.com', 'password': 'x'});
    await auth.accessToken();

    expect(auth.currentSession!.user, {'id': 7, 'name': 'Grace'});
    expect((await store.read())!.user, {'id': 7, 'name': 'Grace'});
  });

  test('state is Authenticated with the carried user after refresh', () async {
    final auth = makeAuth(store);
    await auth.login({'email': 'a@example.com', 'password': 'x'});
    await auth.accessToken();

    final state = auth.state;
    expect(state, isA<Authenticated>());
    expect((state as Authenticated).user, {'id': 7, 'name': 'Ada'});
  });

  test('a login response without a user stores no user', () async {
    loginUser = null;
    final auth = makeAuth(store);
    await auth.login({'email': 'a@example.com', 'password': 'x'});

    expect(auth.currentSession!.user, isNull);
    expect((await store.read())!.user, isNull);
    await auth.accessToken();
    expect(auth.currentSession!.user, isNull);
    expect((await store.read())!.user, isNull);
  });

  test('a failed refresh leaves the stored user untouched', () async {
    final auth = makeAuth(store);
    await auth.login({'email': 'a@example.com', 'password': 'x'});

    refreshHandler = (_) => _json({'message': 'boom'}, 500);
    await expectLater(auth.accessToken(), throwsA(isA<SpAuthError>()));
    expect((await store.read())!.user, {'id': 7, 'name': 'Ada'});
    expect(auth.currentSession!.user, {'id': 7, 'name': 'Ada'});

    refreshHandler = (_) =>
        _json({'success': false, 'message': 'busy', 'error_code': 5000});
    await expectLater(auth.accessToken(), throwsA(isA<SpAuthError>()));
    expect((await store.read())!.user, {'id': 7, 'name': 'Ada'});
  });

  test(
    'cross-isolate: instance adopting a newer stored session keeps user',
    () async {
      final a = makeAuth(store);
      final b = makeAuth(KeyValueTokenStore(storage));
      await a.login({'email': 'a@example.com', 'password': 'x'});
      await b.restore();
      expect(b.currentSession!.accessToken, 'at_login');

      await a.accessToken(); // A refreshes: store now holds at_1 + carried user
      expect(refreshCount, 1);

      await b.accessToken(); // B adopts the newer session instead of refreshing
      expect(refreshCount, 1);
      expect(b.currentSession!.accessToken, 'at_1');
      expect(b.currentSession!.user, {'id': 7, 'name': 'Ada'});
      expect((b.state as Authenticated).user, {'id': 7, 'name': 'Ada'});
    },
  );
}
