import 'cookie_transport.dart';

/// Stub implementation of [BrowserCookieEnv] for non-browser platforms.
class StubBrowserCookieEnv implements BrowserCookieEnv {
  const StubBrowserCookieEnv();

  @override
  bool get isSupported => false;

  @override
  String? getCookie(String name) => null;

  @override
  void setCookie(String name, String value) {}
}

/// Creates default cookie environment for non-browser platforms.
BrowserCookieEnv createDefaultCookieEnv() => const StubBrowserCookieEnv();
