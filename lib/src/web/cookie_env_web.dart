import 'package:web/web.dart' as web;
import 'cookie_transport.dart';

/// Browser implementation of [BrowserCookieEnv] accessing document.cookie.
class WebBrowserCookieEnv implements BrowserCookieEnv {
  const WebBrowserCookieEnv();

  @override
  bool get isSupported => true;

  @override
  String? getCookie(String name) {
    final allCookies = web.document.cookie;
    if (allCookies.isEmpty) return null;
    final parts = allCookies.split(';');
    for (final part in parts) {
      final pair = part.trim().split('=');
      if (pair.isNotEmpty && pair[0] == name) {
        return pair.length > 1 ? pair.sublist(1).join('=') : '';
      }
    }
    return null;
  }

  @override
  void setCookie(String name, String value) {
    web.document.cookie = '$name=$value; path=/; SameSite=Lax';
  }
}

/// Creates default cookie environment for browser platforms.
BrowserCookieEnv createDefaultCookieEnv() => const WebBrowserCookieEnv();
