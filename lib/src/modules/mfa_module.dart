import 'package:dio/dio.dart';
import '../auth_core.dart';
import '../envelope.dart';
import '../session.dart';

/// Module managing multi-factor authentication (MFA) challenges and verification.
class MfaModule {
  /// The underlying authentication client.
  final SpJwtAuth auth;

  /// Creates a new [MfaModule].
  MfaModule(this.auth);

  /// Lists available MFA challenge methods for [challengeId].
  Future<List<String>> listMethods({required String challengeId}) async {
    final uri = auth.endpointUri('/auth/mfa/methods');
    final response = await auth.dio.get<dynamic>(
      uri.toString(),
      queryParameters: {'challenge_id': challengeId},
      options: Options(headers: {'Accept': 'application/json'}),
    );
    final data = response.data;
    if (data is Map<String, dynamic> && data['data'] is List) {
      return (data['data'] as List).map((e) => e.toString()).toList();
    }
    if (data is List) {
      return data.map((e) => e.toString()).toList();
    }
    return [];
  }

  /// Triggers a challenge delivery via [method] for [challengeId].
  Future<Map<String, dynamic>> challenge({
    required String challengeId,
    required String method,
  }) async {
    final uri = auth.endpointUri('/auth/mfa/challenge');
    final response = await auth.dio.post<dynamic>(
      uri.toString(),
      data: {'challenge_id': challengeId, 'method': method},
      options: Options(headers: {'Accept': 'application/json'}),
    );
    return response.data is Map<String, dynamic>
        ? response.data as Map<String, dynamic>
        : {};
  }

  /// Verifies second-factor [code] for [challengeId] and completes login.
  Future<LoginResult> verify({
    required String challengeId,
    required String code,
  }) async {
    final uri = auth.endpointUri('/auth/mfa/verify');
    final response = await auth.dio.post<dynamic>(
      uri.toString(),
      data: {'challenge_id': challengeId, 'code': code},
      options: Options(headers: {'Accept': 'application/json'}),
    );
    final data = response.data;
    throwIfEnvelopeFailure(data);
    final session = auth.endpoints.parseSession(data);
    await auth.store.write(session);
    await auth.restore();
    return AuthenticatedResult(session);
  }
}
