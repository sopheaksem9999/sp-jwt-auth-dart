import 'package:dio/dio.dart';
import '../auth_core.dart';

/// Module managing active user sessions across devices.
class SessionsModule {
  /// The underlying authentication client.
  final SpJwtAuth auth;

  /// Creates a new [SessionsModule].
  SessionsModule(this.auth);

  /// Lists all active sessions for the current user.
  Future<List<Map<String, dynamic>>> list() async {
    final hdrs = await auth.headers();
    final uri = auth.endpointUri('/auth/sessions');
    final response = await auth.send(
      'GET',
      uri.toString(),
      options: Options(headers: {'Accept': 'application/json', ...hdrs}),
    );
    final data = response.data;
    if (data is Map<String, dynamic> && data['data'] is List) {
      return (data['data'] as List).whereType<Map<String, dynamic>>().toList();
    }
    if (data is List) {
      return data.whereType<Map<String, dynamic>>().toList();
    }
    return [];
  }

  /// Revokes an active session by [sessionId].
  Future<void> revoke(String sessionId) async {
    final hdrs = await auth.headers();
    final uri = auth.endpointUri('/auth/sessions/$sessionId');
    await auth.send(
      'DELETE',
      uri.toString(),
      options: Options(headers: {'Accept': 'application/json', ...hdrs}),
    );
  }

  /// Revokes all other active sessions except the current session.
  Future<void> revokeOthers() async {
    final hdrs = await auth.headers();
    final uri = auth.endpointUri('/auth/sessions/revoke-others');
    await auth.send(
      'POST',
      uri.toString(),
      options: Options(headers: {'Accept': 'application/json', ...hdrs}),
    );
  }
}
