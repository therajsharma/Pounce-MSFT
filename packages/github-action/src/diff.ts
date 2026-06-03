export interface DependencyCandidate {
  ecosystem: 'npm' | 'pypi';
  packageName: string;
  version: string;
}

export function extractPackageJsonDependencies(content: string): DependencyCandidate[] {
  const parsed = JSON.parse(content) as {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
    optionalDependencies?: Record<string, string>;
  };

  return [
    ...Object.entries(parsed.dependencies ?? {}),
    ...Object.entries(parsed.devDependencies ?? {}),
    ...Object.entries(parsed.optionalDependencies ?? {})
  ].map(([packageName, version]) => ({
    ecosystem: 'npm' as const,
    packageName,
    version: String(version)
  }));
}

export function extractRequirementsDependencies(content: string): DependencyCandidate[] {
  return content
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'))
    .flatMap((line) => {
      const match = /^([A-Za-z0-9_.-]+)==([A-Za-z0-9_.!+\-]+)$/.exec(line);
      if (!match) return [];
      return [{ ecosystem: 'pypi' as const, packageName: match[1], version: match[2] }];
    });
}

