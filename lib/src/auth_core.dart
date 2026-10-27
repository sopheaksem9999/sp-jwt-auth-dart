import 'dart:async';
import 'package:dio/dio.dart';
import 'claims.dart';
import 'endpoints.dart';
import 'envelope.dart';
import 'errors.dart';
import 'interceptor.dart';
import 'modules/account_module.dart';
import 'modules/mfa_module.dart';
import 'modules/otp_module.dart';
import 'modules/sessions_module.dart';
import 'refresh_lock.dart';
import 'session.dart';
import 'token_store.dart';
import 'url.dart';
import 'web/cookie_transport.dart';
import 'web/tab_sync.dart';

/// Authentication mode for the client.
enum AuthMode {
  /// Standard user session with access and rotating refresh tokens.
  userSession,

  /// Static bearer token that does not rotate.
  staticToken,

  /// OAuth2 client credentials grant.
  clientCredentials,

  /// API key authentication.
  apiKey,
}

/// Core authentication client managing session lifecycle, proactive rotation,
/// single-flight deduplication, and failure classification.
class SpJwtAuth {
  /// Base URL of the authentication server.
  final Uri baseUrl;

  /// Configured authentication endpoints.
  final Endpoints endpoints;

  /// Underlying persistent or in-memory token store.
  final TokenStore store;

  /// Authentication mode.
  final AuthMode mode;

  /// Duration before token expiry when proactive refresh is triggered.
  final Duration refreshAhead;

  final RefreshLock _refreshLock;

  /// HTTP client used for auth requests.
  final Dio dio;

  final StreamController<AuthState> _stateController =
      StreamController<AuthState>.broadcast();
  final StreamController<AuthEvent> _eventsController =
      StreamController<AuthEvent>.broadcast();

  AuthState _state = const Anonymous();
  StoredSession? _cachedSession;
  Future<String?>? _refreshInFlight;
  bool _isHydrated = false;

  /// Optional coordinator for cross-tab synchronisation.
  final TabSync? tabSync;
  StreamSubscription<TabSyncMessage>? _tabSyncSub;

  /// Transport mode for authentication tokens.
  final Transport transport;

  /// Customization of OTP request bodies and challenge-id handling.
  final OtpOptions otpOptions;

  /// CSRF configuration for cookie transport.
  final Csrf csrf;

  final BrowserCookieEnv _cookieEnv;
  String? _csrfToken;

  /// Creates a new [SpJwtAuth] client.
  SpJwtAuth({
    required this.baseUrl,
    required this.endpoints,
    required this.store,
    this.mode = AuthMode.userSession,
    this.refreshAhead = const Duration(seconds: 60),
    this.transport = Transport.body,
    this.csrf = const Csrf(),
    this.tabSync,
    OtpOptions? otpOptions,
    BrowserCookieEnv? cookieEnv,
    RefreshLock? refreshLock,
    Dio? dio,
  }) : otpOptions = otpOptions ?? const OtpOptions(),
       _cookieEnv = cookieEnv ?? defaultCookieEnv(),
       _refreshLock = refreshLock ?? InProcessRefreshLock(),
       dio = dio ?? Dio() {
    if (transport == Transport.cookie && !_cookieEnv.isSupported) {
      throw UnsupportedError(
        'Transport.cookie is only supported in browser environments or when a BrowserCookieEnv is provided.',
      );
    }
    if (tabSync != null) {
      _tabSyncSub = tabSync!.messages.listen((msg) async {
        if (msg is TabLoggedOutMessage) {
          await store.clear();
          _cachedSession = null;
          _setState(const Anonymous());
          _eventsController.add(
            const SessionEnded(
              'Logged out from another tab',
              endReason: SessionEndReason.crossTabLogout,
            ),
          );
        } else if (msg is TabRefreshedMessage) {
          _cachedSession = msg.session;
          _setState(
            Authenticated(
              user: msg.session.user ?? const {},
              claims: _extractClaims(msg.session.accessToken),
            ),
          );
          _eventsController.add(Refreshed(msg.session));
        }
      });
    }
  }

  /// Resolves an endpoint [path] against [baseUrl], honouring
  /// [Endpoints.relativeToBase].
  Uri endpointUri(String path) =>
      resolveEndpoint(baseUrl, path, relativeToBase: endpoints.relativeToBase);

  /// Current authentication state.
  AuthState get state => _state;

  /// Whether persistent storage restoration has settled.
  bool get isHydrated => _isHydrated;

  /// Stream of authentication state changes.
  Stream<AuthState> get changes => _stateController.stream;

  /// Stream of discrete authentication events.
  Stream<AuthEvent> get events => _eventsController.stream;

  void _setState(AuthState newState) {
    if (_state != newState) {
      _state = newState;
      if (!_stateController.isClosed) {
        _stateController.add(newState);
      }
    }
  }

  JwtClaims _extractClaims(String token) {
    try {
      return JwtClaims.parse(token);
    } catch (_) {
      return const JwtClaims(raw: {});
    }
  }

  /// Restores session state from the underlying [store].
  Future<void> restore() async {
    try {
      final session = await store.read();
      if (session != null) {
        _cachedSession = session;
        _setState(
          Authenticated(
            user: session.user ?? const {},
            claims: _extractClaims(session.accessToken),
          ),
        );
      } else {
        _cachedSession = null;
        _setState(const Anonymous());
      }
    } finally {
      _isHydrated = true;
    }
  }

  /// Alias to [restore] guaranteeing storage hydration has settled.
  Future<void> ready() => restore();

  /// Returns a valid access token, proactively refreshing if near expiry.
  Future<String?> accessToken() async {
    if (_cachedSession == null) {
      await restore();
    }
    if (_cachedSession == null) {
      if (transport == Transport.cookie) {
        return _doRefresh();
      }
      return null;
    }

    final now = DateTime.now().toUtc();
    final exp =
        _cachedSession!.expiresAt ??
        _extractClaims(_cachedSession!.accessToken).exp;
    if (exp != null && exp.difference(now) < refreshAhead) {
      return _doRefresh();
    }
    return _cachedSession!.accessToken;
  }

  /// Returns the authorization headers for authenticated requests.
  Future<Map<String, String>> headers() async {
    final token = await accessToken();
    if (token != null && token.isNotEmpty) {
      return {'Authorization': 'Bearer $token'};
    }
    return {};
  }

  /// Handles a 401 response by attempting a single refresh.
  ///
  /// Returns `true` if refresh succeeded and request should be retried.
  Future<bool> handleUnauthorized() async {
    try {
      final token = await _doRefresh(force: true);
      return token != null;
    } catch (_) {
      return false;
    }
  }

  /// Single-flight refresh entrypoint.
  Future<String?> _doRefresh({bool force = false}) {
    if (_refreshInFlight != null) {
      return _refreshInFlight!;
    }
    final future = _executeRefresh(force: force);
    _refreshInFlight = future;
    return future.whenComplete(() {
      _refreshInFlight = null;
    });
  }

  Future<String?> _executeRefresh({bool force = false}) async {
    return _refreshLock.synchronized('refresh', () async {
      // Re-read store first: another isolate or process may have refreshed already.
      final currentInStore = await store.read();
      final now = DateTime.now().toUtc();
      if (currentInStore != null) {
        final tokenChanged =
            _cachedSession != null &&
            currentInStore.accessToken != _cachedSession!.accessToken;
        final exp =
            currentInStore.expiresAt ??
            _extractClaims(currentInStore.accessToken).exp;
        final isFresh = exp != null && exp.difference(now) >= refreshAhead;
        if (tokenChanged || (!force && isFresh)) {
          _cachedSession = currentInStore;
          _setState(
            Authenticated(
              user: currentInStore.user ?? const {},
              claims: _extractClaims(currentInStore.accessToken),
            ),
          );
          return currentInStore.accessToken;
        }
      }

      final isCookie = transport == Transport.cookie;
      String? rt;
      if (!isCookie) {
        rt = currentInStore?.refreshToken ?? _cachedSession?.refreshToken;
        if (rt == null || rt.isEmpty) {
          await _handleDefinitiveFailure('No refresh token available');
          throw const SpAuthError(
            code: SpAuthErrorCode.refreshReuseDetected,
            message: 'No refresh token available',
          );
        }
      }

      final refreshUri = endpointUri(endpoints.refresh);
      _csrfToken ??= _cookieEnv.getCookie(csrf.cookie);

      Future<Response<dynamic>> sendRefreshRequest(String? csrfVal) {
        return dio.post<dynamic>(
          refreshUri.toString(),
          data: isCookie ? null : {'refresh_token': rt},
          options: Options(
            extra: {if (isCookie) 'withCredentials': true},
            headers: {
              'Accept': 'application/json',
              if (isCookie && csrfVal != null && csrfVal.isNotEmpty)
                csrf.header: csrfVal,
            },
          ),
        );
      }

      try {
        Response<dynamic> response;
        try {
          response = await sendRefreshRequest(_csrfToken);
        } on DioException catch (e) {
          if (isCookie && e.response?.statusCode == 403) {
            final data = e.response?.data;
            final isCsrfErr =
                data is Map &&
                (data['code'] == 'csrf_failed' ||
                    (data['message']?.toString().toLowerCase().contains(
                          'csrf',
                        ) ??
                        false));
            if (isCsrfErr) {
              final liveCsrf = _cookieEnv.getCookie(csrf.cookie);
              if (liveCsrf != null && liveCsrf != _csrfToken) {
                _csrfToken = liveCsrf;
                response = await sendRefreshRequest(_csrfToken);
              } else {
                rethrow;
              }
            } else {
              rethrow;
            }
          } else {
            rethrow;
          }
        }

        final headerVals = response.headers[csrf.header];
        if (headerVals != null && headerVals.isNotEmpty) {
          _csrfToken = headerVals.first;
        }

        final data = response.data;
        if (data is Map<String, dynamic>) {
          if (data['success'] == false) {
            final errCode = data['error_code'];
            final msg = (data['message'] as String?)?.toLowerCase() ?? '';
            if (errCode == 10002 ||
                errCode == 10010 ||
                msg.contains('unauthenticated') ||
                msg.contains('revoked')) {
              final rawMsg = data['message']?.toString() ?? 'Token revoked';
              await _handleDefinitiveFailure(
                rawMsg,
                SessionEndReason.refreshRejected,
              );
              throw SpAuthError(
                code: SpAuthErrorCode.refreshReuseDetected,
                message: rawMsg,
                errorCode: errCode is int ? errCode : null,
              );
            }
          }
        }

        throwIfEnvelopeFailure(data);
        final newSession = endpoints.parseSession(data);
        await store.write(newSession);
        _cachedSession = newSession;
        _setState(
          Authenticated(
            user: newSession.user ?? const {},
            claims: _extractClaims(newSession.accessToken),
          ),
        );
        _eventsController.add(Refreshed(newSession));
        tabSync?.notifyRefreshed(newSession);
        return newSession.accessToken;
      } on DioException catch (e) {
        final classified = _classifyDioError(e);
        if (classified.isDefinitive) {
          final endReason = classified.code == SpAuthErrorCode.tokenExpired
              ? SessionEndReason.tokenExpired
              : SessionEndReason.refreshRejected;
          await _handleDefinitiveFailure(classified.message, endReason);
        }
        throw SpAuthError(
          code: classified.code,
          message: classified.message,
          cause: e,
        );
      } catch (e) {
        if (e is SpAuthError) rethrow;
        throw SpAuthError(
          code: SpAuthErrorCode.unknown,
          message: e.toString(),
          cause: e,
        );
      }
    });
  }

  Future<void> _handleDefinitiveFailure(
    String reason, [
    SessionEndReason endReason = SessionEndReason.refreshRejected,
  ]) async {
    await store.clear();
    _cachedSession = null;
    _setState(const Anonymous());
    _eventsController.add(SessionEnded(reason, endReason: endReason));
  }

  _ClassifiedError _classifyDioError(DioException e) {
    if (e.type == DioExceptionType.connectionTimeout ||
        e.type == DioExceptionType.sendTimeout ||
        e.type == DioExceptionType.receiveTimeout) {
      return _ClassifiedError(
        isDefinitive: false,
        code: SpAuthErrorCode.timeout,
        message: 'Request timed out: ${e.message ?? 'timeout'}',
      );
    }

    if (e.type == DioExceptionType.connectionError) {
      return _ClassifiedError(
        isDefinitive: false,
        code: SpAuthErrorCode.network,
        message:
            'Network connection error: ${e.message ?? 'connection failed'}',
      );
    }

    final response = e.response;
    if (response != null) {
      final status = response.statusCode ?? 500;
      final data = response.data;

      var bodyText = '';
      int? errorCode;
      if (data is Map<String, dynamic>) {
        bodyText = '${data['message'] ?? ''} ${data['error'] ?? ''}'
            .trim()
            .toLowerCase();
        final codeVal = data['error_code'];
        if (codeVal is int) {
          errorCode = codeVal;
        } else if (codeVal is String) {
          errorCode = int.tryParse(codeVal);
        }
      } else if (data is String) {
        bodyText = data.toLowerCase();
      }

      final hasUnauthenticated =
          bodyText.contains('unauthenticated') || bodyText.contains('revoked');
      final isDefinitiveCode = errorCode == 10002 || errorCode == 10010;
      final isDefinitiveStatus =
          status == 400 || status == 401 || status == 403 || status == 422;

      if (hasUnauthenticated || isDefinitiveCode || isDefinitiveStatus) {
        return _ClassifiedError(
          isDefinitive: true,
          code: isDefinitiveCode
              ? SpAuthErrorCode.refreshReuseDetected
              : (status == 403
                    ? SpAuthErrorCode.forbidden
                    : SpAuthErrorCode.unauthenticated),
          message: bodyText.isNotEmpty
              ? bodyText
              : 'Authentication failed (HTTP $status)',
        );
      }

      if (status >= 500) {
        return _ClassifiedError(
          isDefinitive: false,
          code: SpAuthErrorCode.network,
          message: 'Server error (HTTP $status)',
        );
      }
    }

    return _ClassifiedError(
      isDefinitive: false,
      code: SpAuthErrorCode.network,
      message: e.message ?? 'Network error',
    );
  }

  /// Lifecycle notification triggered when application returns to foreground.
  ///
  /// Silently checks token expiry and triggers a proactive single-flight refresh.
  void onResumed() {
    scheduleMicrotask(() async {
      try {
        if (_cachedSession == null) {
          await restore();
        }
        if (_cachedSession != null) {
          final now = DateTime.now().toUtc();
          final exp =
              _cachedSession!.expiresAt ??
              _extractClaims(_cachedSession!.accessToken).exp;
          if (exp != null && exp.difference(now) < refreshAhead) {
            await _doRefresh();
          }
        }
      } catch (_) {
        // Foreground refresh on resume is silent.
      }
    });
  }

  /// Authenticates with user credentials and stores the resulting session.
  ///
  /// Returns [SecondFactorRequiredResult] if MFA challenge is issued,
  /// or [AuthenticatedResult] upon successful login.
  Future<LoginResult> login(Map<String, dynamic> credentials) async {
    final uri = endpointUri(endpoints.login);
    final response = await dio.post<dynamic>(
      uri.toString(),
      data: credentials,
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
    final session = endpoints.parseSession(data);
    await store.write(session);
    _cachedSession = session;
    _setState(
      Authenticated(
        user: session.user ?? const {},
        claims: _extractClaims(session.accessToken),
      ),
    );
    return AuthenticatedResult(session);
  }

  /// Fetches current user profile from the configured whoami endpoint.
  Future<Map<String, dynamic>> whoami() async {
    final hdrs = await headers();
    final uri = endpointUri(endpoints.whoami);
    final response = await dio.get<dynamic>(
      uri.toString(),
      options: Options(headers: {'Accept': 'application/json', ...hdrs}),
    );
    final data = response.data;
    if (data is Map<String, dynamic>) {
      return data;
    }
    return {'data': data};
  }

  /// Attaches an authentication and auto-refresh interceptor to [dio].
  Interceptor attach(Dio dio) {
    final interceptor = SpJwtAuthInterceptor(this, dio);
    dio.interceptors.add(interceptor);
    return interceptor;
  }

  /// Removes all interceptors managed by this [SpJwtAuth] instance from [dio].
  void detach(Dio dio) {
    dio.interceptors.removeWhere(
      (i) => i is SpJwtAuthInterceptor && i.auth == this,
    );
  }

  /// Logs out the user, attempting remote revocation and clearing local storage.
  Future<void> logout() async {
    final currentRt = _cachedSession?.refreshToken;
    final currentAt = _cachedSession?.accessToken;
    try {
      final uri = endpointUri(endpoints.logout);
      await dio.post<dynamic>(
        uri.toString(),
        data: currentRt != null ? {'refresh_token': currentRt} : null,
        options: Options(
          headers: {
            'Accept': 'application/json',
            if (currentAt != null) 'Authorization': 'Bearer $currentAt',
          },
        ),
      );
    } catch (_) {
      // Best-effort remote revocation: local session cleared regardless.
    } finally {
      tabSync?.notifyLoggedOut();
      await store.clear();
      _cachedSession = null;
      _setState(const Anonymous());
      _eventsController.add(
        const SessionEnded(
          'User logged out',
          endReason: SessionEndReason.manualLogout,
        ),
      );
    }
  }

  /// One-time password (OTP) operations.
  late final OtpModule otp = OtpModule(this);

  /// Multi-factor authentication (MFA) operations.
  MfaModule get mfa => MfaModule(this);

  /// Active session management operations.
  SessionsModule get sessions => SessionsModule(this);

  /// Account profile and password operations.
  AccountModule get account => AccountModule(this);

  /// Closes stream controllers and releases resources.
  Future<void> dispose() async {
    await _tabSyncSub?.cancel();
    await _stateController.close();
    await _eventsController.close();
  }
}

class _ClassifiedError {
  final bool isDefinitive;
  final SpAuthErrorCode code;
  final String message;

  _ClassifiedError({
    required this.isDefinitive,
    required this.code,
    required this.message,
  });
}
