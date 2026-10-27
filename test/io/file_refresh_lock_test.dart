import 'dart:io';
import 'package:sp_jwt_auth/io.dart';
import 'package:test/test.dart';

void main() {
  test(
    'FileRefreshLock serializes execution across distinct lock instances',
    () async {
      final tempDir = Directory.systemTemp.createTempSync('sp_file_lock_test_');
      try {
        final lock1 = FileRefreshLock(lockDir: tempDir);
        final lock2 = FileRefreshLock(lockDir: tempDir);
        final log = <String>[];

        final f1 = lock1.synchronized('token_key', () async {
          log.add('start1');
          await Future<void>.delayed(const Duration(milliseconds: 30));
          log.add('end1');
          return 1;
        });

        final f2 = lock2.synchronized('token_key', () async {
          log.add('start2');
          log.add('end2');
          return 2;
        });

        final results = await Future.wait([f1, f2]);
        expect(results, equals([1, 2]));
        expect(log, equals(['start1', 'end1', 'start2', 'end2']));
      } finally {
        try {
          tempDir.deleteSync(recursive: true);
        } catch (_) {}
      }
    },
  );
}
