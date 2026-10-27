import 'dart:async';
import 'package:dio/dio.dart';
import 'auth_core.dart';

/// Interceptor that transparently adds Authorization headers and handles single-retry 401 recovery.
class SpJwtAuthInterceptor extends QueuedInterceptor {
  /// The authentication client managing session tokens.
  final SpJwtAuth auth;

  /// The Dio client instance through which retried requests are executed.
  final Dio dio;

  /// Creates a new [SpJwtAuthInterceptor].
  SpJwtAuthInterceptor(this.auth, this.dio);

  @override
  Future<void> onRequest(
    RequestOptions options,
    RequestInterceptorHandler handler,
  ) async {
    if (options.extra['skipAuth'] == true) {
      return handler.next(options);
    }

    try {
      final token = await auth.accessToken();
      if (token != null && token.isNotEmpty) {
        options.headers['Authorization'] = 'Bearer $token';
      }
      handler.next(options);
    } catch (_) {
      handler.next(options);
    }
  }

  @override
  Future<void> onError(
    DioException err,
    ErrorInterceptorHandler handler,
  ) async {
    final options = err.requestOptions;
    final statusCode = err.response?.statusCode;

    // Skip retry if auth is disabled, already handled externally, already retried, or not 401.
    if (options.extra['skipAuth'] == true ||
        options.extra['skipRefresh'] == true ||
        options.extra['sp.authHandled'] == true ||
        options.extra['sp.retried'] == true ||
        statusCode != 401) {
      return handler.next(err);
    }

    // Mark as retried to guarantee at most one retry.
    options.extra['sp.retried'] = true;

    final success = await auth.handleUnauthorized();
    if (!success) {
      return handler.next(err);
    }

    try {
      final newToken = await auth.accessToken();
      if (newToken != null && newToken.isNotEmpty) {
        options.headers['Authorization'] = 'Bearer $newToken';
      }
      final response = await dio.fetch<dynamic>(options);
      return handler.resolve(response);
    } on DioException catch (retryErr) {
      return handler.next(retryErr);
    } catch (e) {
      return handler.next(err);
    }
  }
}
