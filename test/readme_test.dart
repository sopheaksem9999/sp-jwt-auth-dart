import 'dart:io';

import 'package:sp_jwt_auth/sp_jwt_auth.dart';
import 'package:test/test.dart';

void main() {
  final readme = File('README.md').readAsStringSync();

  test('README does not pin a beta version', () {
    expect(readme, isNot(contains('^0.1.0-beta')));
    expect(readme, contains('^0.2.0'));
  });

  test('README documents the 0.1.x additions', () {
    expect(readme, contains('relativeToBase'));
    expect(readme, contains('addListener'));
    expect(readme, contains('attach(dio)'));
    expect(readme, contains('sp_jwt_auth_flutter'));
  });

  test('SecureStorage classes are attributed to the companion package', () {
    // Classes exported by this package; anything else must be companion-only.
    final exported = <String>{'KeyValueTokenStore', 'MemoryTokenStore'};
    expect(
      [KeyValueTokenStore, MemoryTokenStore].map((t) => t.toString()),
      containsAll(exported),
    );
    final names = RegExp(r'\bSecureStorage\w*').allMatches(readme);
    expect(names, isNotEmpty);
    for (final m in names) {
      final name = m.group(0)!;
      expect(exported, isNot(contains(name)));
      // Same line or the surrounding paragraph must name the companion.
      final start = readme.lastIndexOf('\n\n', m.start);
      final end = readme.indexOf('\n\n', m.end);
      final para = readme.substring(
        start < 0 ? 0 : start,
        end < 0 ? readme.length : end,
      );
      expect(
        para.contains('sp_jwt_auth_flutter'),
        isTrue,
        reason: '$name must be attributed to sp_jwt_auth_flutter:\n$para',
      );
    }
  });

  test('README gives no unresolvable path dependency for the companion', () {
    expect(readme, isNot(contains('../sp-jwt-auth-flutter')));
    expect(readme, contains('implements KeyValueStorage'));
    expect(readme, contains('FlutterSecureStorage'));
  });

  test('README links an existing test file for each linked test path', () {
    final links = RegExp(r'\]\((test/[^)#]+)').allMatches(readme);
    expect(links, isNotEmpty);
    for (final m in links) {
      expect(File(m.group(1)!).existsSync(), isTrue, reason: m.group(1));
    }
  });
}
