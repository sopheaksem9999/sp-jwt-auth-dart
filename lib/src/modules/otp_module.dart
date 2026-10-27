import 'package:dio/dio.dart';
import '../auth_core.dart';
import '../envelope.dart';
import '../session.dart';

/// Module managing one-time password (OTP) delivery and verification.
class OtpModule {
  /// The underlying authentication client.
  final SpJwtAuth auth;

  /// Creates a new [OtpModule].
  OtpModule(this.auth);

  /// Requests an OTP to be sent to the given [identifier] via optional [channel].
  Future<void> sendOtp({required String identifier, String? channel}) async {
    final uri = auth.endpointUri('/auth/otp/send');
    await auth.dio.post<dynamic>(
      uri.toString(),
      data: {'identifier': identifier, if (channel != null) 'channel': channel},
      options: Options(headers: {'Accept': 'application/json'}),
    );
  }

  /// Verifies an OTP [code] for [identifier], storing the resulting session on success.
  Future<LoginResult> verifyOtp({
    required String identifier,
    required String code,
  }) async {
    final uri = auth.endpointUri('/auth/otp/verify');
    final response = await auth.dio.post<dynamic>(
      uri.toString(),
      data: {'identifier': identifier, 'code': code},
      options: Options(headers: {'Accept': 'application/json'}),
    );
    final data = response.data;
    if (data is Map<String, dynamic>) {
      final mfaRequired =
          data['mfa_required'] == true || data['requires_mfa'] == true;
      final challengeId = (data['challenge_id'] ?? data['challengeId'])
          ?.toString();
      if (mfaRequired && challengeId != null && challengeId.isNotEmpty) {
        return SecondFactorRequiredResult(challengeId);
      }
    }

    throwIfEnvelopeFailure(data);
    final session = auth.endpoints.parseSession(data);
    await auth.store.write(session);
    await auth.restore();
    return AuthenticatedResult(session);
  }
}
