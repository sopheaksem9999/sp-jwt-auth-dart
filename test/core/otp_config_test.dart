import 'dart:convert';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:sp_jwt_auth/sp_jwt_auth.dart';
import 'package:test/test.dart';

class _Adapter implements HttpClientAdapter {
  final List<RequestOptions> requests = [];
  final Map<String, dynamic> Function(RequestOptions) handler;
  _Adapter(this.handler);

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future<void>? cancelFuture,
  ) async {
    requests.add(options);
    return ResponseBody.fromString(
      jsonEncode(handler(options)),
      200,
      headers: {
        Headers.contentTypeHeader: ['application/json'],
      },
    );
  }

  @override
  void close({bool force = false}) {}
}

Map<String, dynamic> _session() => {
  'success': true,
  'data': {'access_token': 'tok', 'refresh_token': 'ref', 'expires_in': 900},
};

void main() {
  late _Adapter adapter;
  late MemoryTokenStore store;

  SpJwtAuth build({
    Endpoints endpoints = const Endpoints(),
    OtpOptions? otpOptions,
    Map<String, dynamic> Function(RequestOptions)? handler,
  }) {
    adapter = _Adapter(
      handler ??
          (o) => o.path.contains('verify') ? _session() : {'success': true},
    );
    store = MemoryTokenStore();
    return SpJwtAuth(
      baseUrl: Uri.parse('https://api.example.com'),
      endpoints: endpoints,
      store: store,
      otpOptions: otpOptions,
      dio: Dio()..httpClientAdapter = adapter,
    );
  }

  Map<String, dynamic> sendOk() => {
    'otp_id': 'otp-1',
    'destination_masked': 'a***@example.com',
    'expires_in': 300,
  };

  test('defaults post to /otp/request and /otp/verify', () async {
    final auth = build();
    await auth.otp.sendOtp(identifier: 'a@example.com', channel: 'email');
    await auth.otp.verifyOtp(identifier: 'a@example.com', code: '123456');
    expect(adapter.requests[0].uri.path, '/otp/request');
    expect(adapter.requests[1].uri.path, '/otp/verify');
  });

  test('send body is {destination, channel, purpose}', () async {
    final auth = build();
    await auth.otp.sendOtp(identifier: 'a@example.com', channel: 'email');
    expect(adapter.requests[0].data, {
      'destination': 'a@example.com',
      'channel': 'email',
      'purpose': 'login',
    });
    await auth.otp.sendOtp(
      identifier: 'a@example.com',
      channel: 'email',
      purpose: 'signup',
    );
    expect((adapter.requests[1].data as Map)['purpose'], 'signup');
  });

  test(
    'verify body carries otp_id captured from the 202 response (also when nested under data)',
    () async {
      var auth = build(
        handler: (o) => o.path.contains('verify') ? _session() : sendOk(),
      );
      await auth.otp.sendOtp(identifier: 'a@example.com', channel: 'email');
      await auth.otp.verifyOtp(identifier: 'a@example.com', code: '123456');
      expect(adapter.requests[1].data, {
        'otp_id': 'otp-1',
        'code': '123456',
        'destination': 'a@example.com',
        'channel': 'email',
      });

      auth = build(
        handler: (o) => o.path.contains('verify')
            ? _session()
            : {'success': true, 'data': sendOk()},
      );
      await auth.otp.sendOtp(identifier: 'a@example.com', channel: 'email');
      await auth.otp.verifyOtp(identifier: 'a@example.com', code: '123456');
      expect((adapter.requests[1].data as Map)['otp_id'], 'otp-1');
    },
  );

  test(
    'resend default posts to /otp/resend with otp_id, destination, channel',
    () async {
      final auth = build(
        handler: (o) => o.path.contains('verify') ? _session() : sendOk(),
      );
      await auth.otp.sendOtp(identifier: 'a@example.com', channel: 'email');
      await auth.otp.resendOtp(identifier: 'a@example.com');
      expect(adapter.requests[1].uri.path, '/otp/resend');
      expect(adapter.requests[1].data, {
        'otp_id': 'otp-1',
        'destination': 'a@example.com',
        'channel': 'email',
      });
    },
  );

  test('old paths still work when set explicitly', () async {
    final auth = build(
      endpoints: const Endpoints(
        otpSend: '/auth/otp/send',
        otpVerify: '/auth/otp/verify',
        otpResend: '/auth/otp/resend',
      ),
    );
    await auth.otp.sendOtp(identifier: 'a@example.com', channel: 'email');
    await auth.otp.verifyOtp(identifier: 'a@example.com', code: '1');
    expect(adapter.requests[0].uri.path, '/auth/otp/send');
    expect(adapter.requests[1].uri.path, '/auth/otp/verify');
  });

  test('custom otpSend/otpVerify paths are called', () async {
    final auth = build(
      endpoints: const Endpoints(otpSend: '/x/send', otpVerify: '/x/verify'),
    );
    await auth.otp.sendOtp(identifier: 'a');
    await auth.otp.verifyOtp(identifier: 'a', code: '1');
    expect(adapter.requests[0].uri.path, '/x/send');
    expect(adapter.requests[1].uri.path, '/x/verify');
  });

  test(
    'challengeIdFrom captures id from send response and verifyBody adds it',
    () async {
      final auth = build(
        otpOptions: OtpOptions(
          challengeIdFrom: (r) => (r as Map)['challenge'] as String?,
          verifyBody: (id, code, challengeId) => {
            'phone': id,
            'otp': code,
            'challenge_id': challengeId,
          },
        ),
        handler: (o) => o.path.contains('verify')
            ? _session()
            : {'success': true, 'challenge': 'ch-1'},
      );
      await auth.otp.sendOtp(identifier: '+100');
      await auth.otp.verifyOtp(identifier: '+100', code: '9');
      expect(adapter.requests[1].data, {
        'phone': '+100',
        'otp': '9',
        'challenge_id': 'ch-1',
      });
    },
  );

  test('sendBody customizes the send request', () async {
    final auth = build(
      otpOptions: OtpOptions(
        sendBody: (id, channel) => {'to': id, 'via': channel ?? 'sms'},
      ),
    );
    await auth.otp.sendOtp(identifier: 'a');
    expect(adapter.requests[0].data, {'to': 'a', 'via': 'sms'});
  });

  test('successful verify writes session and state is Authenticated', () async {
    final auth = build();
    final result = await auth.otp.verifyOtp(identifier: 'a', code: '1');
    expect(result, isA<AuthenticatedResult>());
    expect((await store.read())?.accessToken, 'tok');
    expect(auth.state, isA<Authenticated>());
  });

  test('auth.otp returns the same instance', () {
    final auth = build();
    expect(identical(auth.otp, auth.otp), isTrue);
  });

  test('resendOtp with otpResend null throws StateError', () async {
    final auth = build(endpoints: const Endpoints(otpResend: null));
    await expectLater(
      auth.otp.resendOtp(identifier: 'a'),
      throwsA(isA<StateError>()),
    );
  });

  test('resendOtp before any send throws StateError', () async {
    final auth = build();
    await expectLater(
      auth.otp.resendOtp(identifier: 'a'),
      throwsA(isA<StateError>()),
    );
  });

  test('resendOtp with custom path and sendBody builder overrides', () async {
    final auth = build(
      endpoints: const Endpoints(otpResend: '/x/resend'),
      otpOptions: OtpOptions(sendBody: (id, channel) => {'to': id}),
    );
    await auth.otp.resendOtp(identifier: 'a');
    expect(adapter.requests.single.uri.path, '/x/resend');
    expect(adapter.requests.single.data, {'to': 'a'});
  });
}
