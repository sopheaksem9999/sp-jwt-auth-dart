import 'dart:async';

/// Abstract lock contract to coordinate refresh attempts across callers,
/// isolates, or browser tabs.
abstract interface class RefreshLock {
  /// Execute [body] exclusively under the lock associated with [key].
  Future<T> synchronized<T>(String key, Future<T> Function() body);
}

/// In-process lock implementation using serialized async task chaining.
class InProcessRefreshLock implements RefreshLock {
  final Map<String, Future<dynamic>> _chains = {};

  @override
  Future<T> synchronized<T>(String key, Future<T> Function() body) {
    final previous = _chains[key] ?? Future<void>.value();
    final completer = Completer<T>();

    _chains[key] = previous.then((_) async {
      try {
        final result = await body();
        completer.complete(result);
      } catch (e, st) {
        completer.completeError(e, st);
      }
    });

    // Cleanup chain entry once finished
    _chains[key]!.whenComplete(() {
      if (_chains[key] == previous) {
        _chains.remove(key);
      }
    });

    return completer.future;
  }
}
