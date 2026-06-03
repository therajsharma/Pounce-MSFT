import { describe, expect, it } from 'vitest';
import { extractPackageJsonDependencies, extractRequirementsDependencies } from './diff.js';

describe('manifest extraction', () => {
  it('extracts npm dependencies from package.json content', () => {
    const dependencies = extractPackageJsonDependencies('{"dependencies":{"lodash":"4.17.21"},"devDependencies":{"axios":"1.8.2"}}');

    expect(dependencies).toEqual([
      { ecosystem: 'npm', packageName: 'lodash', version: '4.17.21' },
      { ecosystem: 'npm', packageName: 'axios', version: '1.8.2' }
    ]);
  });

  it('extracts exact PyPI requirements only', () => {
    const dependencies = extractRequirementsDependencies('requests==2.32.5\nflask>=3\n# comment\n');

    expect(dependencies).toEqual([
      { ecosystem: 'pypi', packageName: 'requests', version: '2.32.5' }
    ]);
  });
});
