import 'dart:async';
import 'dart:convert';
import 'dart:io';
import '../refresh_lock.dart';

/// Cross-isolate file-based lock implementation using OS file locks.
class FileRefreshLock implements RefreshLock {
  final Directory lockDir;
  static final InProcessRefreshLock _inProcess = InProcessRefreshLock();

  FileRefreshLock({Directory? lockDir})
      : lockDir = lockDir ?? Directory('${Directory.systemTemp.path}/sp_jwt_auth_locks') {
    if (!this.lockDir.existsSync()) {
      try {
        this.lockDir.createSync(recursive: true);
      } catch (_) {}
    }
  }

  String _sanitizeKey(String key) {
    final bytes = utf8.encode(key);
    final buffer = StringBuffer();
    for (final b in bytes) {
      buffer.write(b.toRadixString(16).padLeft(2, '0'));
    }
    return buffer.toString();
  }

  @override
  Future<T> synchronized<T>(String key, Future<T> Function() body) {
    return _inProcess.synchronized(key, () async {
      final sanitized = _sanitizeKey(key);
      final lockFile = File('${lockDir.path}/$sanitized.lock');
      if (!lockFile.existsSync()) {
        try {
          lockFile.createSync(recursive: true);
        } catch (_) {}
      }

      final raf = await lockFile.open(mode: FileMode.write);
      try {
        await raf.lock(FileLock.blockingExclusive);
        return await body();
      } finally {
        try {
          await raf.unlock();
        } catch (_) {}
        try {
          await raf.close();
        } catch (_) {}
      }
    });
  }
}
