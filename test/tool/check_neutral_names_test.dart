import 'dart:io';
import 'package:test/test.dart';

void main() {
  test('check_neutral_names passes on clean tree with forbidden names set', () {
    final result = Process.runSync(
      'dart',
      ['tool/check_neutral_names.dart'],
      environment: {'FORBIDDEN_NAMES': 'forbiddenone,forbiddentwo'},
    );
    expect(result.exitCode, equals(0));
  });

  test('check_neutral_names detects forbidden token in temp string', () {
    final result = Process.runSync(
      'dart',
      [
        'tool/check_neutral_names.dart',
        '--test-string',
        'hello forbiddenone world',
      ],
      environment: {'FORBIDDEN_NAMES': 'forbiddenone'},
    );
    expect(result.exitCode, equals(1));
    expect(result.stderr.toString(), contains('Forbidden name found'));
  });
}
