import 'dart:async';
import 'package:sp_jwt_auth/src/refresh_lock.dart';
import 'package:test/test.dart';

void main() {
  test(
    'InProcessRefreshLock serializes concurrent executions for same key',
    () async {
      final lock = InProcessRefreshLock();
      final log = <String>[];

      final f1 = lock.synchronized('k1', () async {
        log.add('start1');
        await Future<void>.delayed(const Duration(milliseconds: 20));
        log.add('end1');
        return 'res1';
      });

      final f2 = lock.synchronized('k1', () async {
        log.add('start2');
        log.add('end2');
        return 'res2';
      });

      final results = await Future.wait([f1, f2]);
      expect(results, equals(['res1', 'res2']));
      expect(log, equals(['start1', 'end1', 'start2', 'end2']));
    },
  );

  test(
    'InProcessRefreshLock allows parallel execution for different keys',
    () async {
      final lock = InProcessRefreshLock();
      final log = <String>[];

      final f1 = lock.synchronized('k1', () async {
        log.add('start1');
        await Future<void>.delayed(const Duration(milliseconds: 30));
        log.add('end1');
      });

      final f2 = lock.synchronized('k2', () async {
        log.add('start2');
        await Future<void>.delayed(const Duration(milliseconds: 10));
        log.add('end2');
      });

      await Future.wait([f1, f2]);
      expect(log, equals(['start1', 'start2', 'end2', 'end1']));
    },
  );
}
