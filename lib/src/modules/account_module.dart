import 'package:dio/dio.dart';
import '../auth_core.dart';

/// Module managing user profile and credential updates.
class AccountModule {
  /// The underlying authentication client.
  final SpJwtAuth auth;

  /// Creates a new [AccountModule].
  AccountModule(this.auth);

  /// Retrieves the current user profile.
  Future<Map<String, dynamic>> profile() => auth.whoami();

  /// Updates profile attributes for the current user.
  Future<Map<String, dynamic>> updateProfile(Map<String, dynamic> data) async {
    final hdrs = await auth.headers();
    final uri = auth.endpointUri('/auth/account/profile');
    final response = await auth.send(
      'PUT',
      uri.toString(),
      data: data,
      options: Options(headers: {'Accept': 'application/json', ...hdrs}),
    );
    return response.data is Map<String, dynamic>
        ? response.data as Map<String, dynamic>
        : {'data': response.data};
  }

  /// Changes the user password given [currentPassword] and [newPassword].
  Future<void> changePassword({
    required String currentPassword,
    required String newPassword,
  }) async {
    final hdrs = await auth.headers();
    final uri = auth.endpointUri('/auth/account/change-password');
    await auth.send(
      'POST',
      uri.toString(),
      data: {'current_password': currentPassword, 'new_password': newPassword},
      options: Options(headers: {'Accept': 'application/json', ...hdrs}),
    );
  }
}
