import { describe, expect, it } from 'vitest';
import { parseBunLock, parsePackageLock, parsePnpmLock, parseYarnLock } from '../src/parsers/npm.ts';
import {
  parseCargoLock,
  parseComposerLock,
  parseGemfileLock,
  parseGoMod,
  parseGradleLockfile,
  parsePipfileLock,
  parsePythonTomlLock,
  parseRequirements,
} from '../src/parsers/others.ts';
import { fromPurl, parseSbom } from '../src/parsers/sbom.ts';
import { parserFor } from '../src/parsers/index.ts';

const pairs = (deps: { name: string; version: string }[]) => deps.map((d) => `${d.name}@${d.version}`);

describe('npm', () => {
  it('reads package-lock v3 packages, including nested and scoped, skipping root and links', () => {
    const lock = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'app', version: '1.0.0' },
        'node_modules/jquery': { version: '3.7.1' },
        'node_modules/@babel/core': { version: '7.24.0' },
        'node_modules/a/node_modules/jquery': { version: '1.12.4' },
        'node_modules/local': { link: true, resolved: 'packages/local' },
        'packages/local': { version: '0.0.1' },
      },
    });
    expect(pairs(parsePackageLock(lock))).toEqual(['jquery@3.7.1', '@babel/core@7.24.0', 'jquery@1.12.4']);
  });

  it('reads an npm alias from the package name in package-lock v2+', () => {
    const lock = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'app', version: '1.0.0' },
        'node_modules/foo': { name: 'bar', version: '1.2.3' },
        'node_modules/@scope/alias': { name: '@real/pkg', version: '3.1.0' },
      },
    });
    expect(pairs(parsePackageLock(lock))).toEqual(['bar@1.2.3', '@real/pkg@3.1.0']);
  });

  it('reads package-lock v1 nested dependencies', () => {
    const lock = JSON.stringify({
      lockfileVersion: 1,
      dependencies: {
        lodash: { version: '4.17.20', dependencies: { minimist: { version: '1.2.5' } } },
        local: { version: 'file:../local' },
      },
    });
    expect(pairs(parsePackageLock(lock))).toEqual(['lodash@4.17.20', 'minimist@1.2.5']);
  });

  it('reads pnpm v9, v6 and v5 keys, dropping peer suffixes', () => {
    const lock = `lockfileVersion: '9.0'
packages:
  '@babel/core@7.24.0':
    resolution: {integrity: x}
  react-dom@18.2.0(react@18.2.0):
    resolution: {integrity: x}
  /lodash@4.17.21:
    resolution: {integrity: x}
  /@types/node/20.1.0:
    resolution: {integrity: x}
`;
    expect(pairs(parsePnpmLock(lock))).toEqual([
      '@babel/core@7.24.0',
      'react-dom@18.2.0',
      'lodash@4.17.21',
      '@types/node@20.1.0',
    ]);
  });

  it('reads every document of a multi-document pnpm lockfile', () => {
    const lock = `---
lockfileVersion: '9.0'
packages:
  pnpm@10.0.0:
    resolution: {integrity: x}
---
lockfileVersion: '9.0'
packages:
  lodash@4.17.21:
    resolution: {integrity: x}
`;
    expect(pairs(parsePnpmLock(lock))).toEqual(['pnpm@10.0.0', 'lodash@4.17.21']);
  });

  it('reads yarn classic', () => {
    const lock = `# yarn lockfile v1


"@babel/core@^7.0.0", "@babel/core@^7.1.0":
  version "7.24.0"
  resolved "https://registry.yarnpkg.com/x"

jquery@^3.0.0:
  version "3.7.1"
`;
    expect(pairs(parseYarnLock(lock))).toEqual(['@babel/core@7.24.0', 'jquery@3.7.1']);
  });

  it('reads yarn berry, skipping metadata and workspaces', () => {
    const lock = `__metadata:
  version: 8
  cacheKey: 10

"app@workspace:.":
  version: 0.0.0-use.local
  resolution: "app@workspace:."

"jquery@npm:^3.0.0":
  version: 3.7.1
  resolution: "jquery@npm:3.7.1"
`;
    expect(pairs(parseYarnLock(lock))).toEqual(['jquery@3.7.1']);
  });

  it('strips pnpm v5 peer suffixes that follow the version', () => {
    const lock = `lockfileVersion: 5.4
packages:
  /@babel/core/7.20.0_@babel+preset-env@7.5.0:
    resolution: {integrity: x}
  /react-dom/18.2.0_react@18.2.0:
    resolution: {integrity: x}
  /some_pkg/1.0.0:
    resolution: {integrity: x}
`;
    expect(pairs(parsePnpmLock(lock))).toEqual(['@babel/core@7.20.0', 'react-dom@18.2.0', 'some_pkg@1.0.0']);
  });

  it('reads the real package name from yarn berry patch and alias headers', () => {
    const lock = `"lodash@patch:lodash@npm%3A4.17.21#./patches/lodash.patch::version=4.17.21&hash=abc":
  version: 4.17.21

"foo@npm:bar@^1.0.0":
  version: 1.2.3

"@scope/x@patch:@scope/x@npm%3A2.0.0#~builtin<compat/x>":
  version: 2.0.0

"@a/b@npm:@c/d@^3.0.0":
  version: 3.1.0
`;
    expect(pairs(parseYarnLock(lock))).toEqual(['lodash@4.17.21', 'bar@1.2.3', '@scope/x@2.0.0', '@c/d@3.1.0']);
  });

  it('reads npm: aliases in package-lock v1 as the aliased package', () => {
    const lock = JSON.stringify({
      lockfileVersion: 1,
      dependencies: {
        foo: { version: 'npm:bar@1.2.3' },
        scoped: { version: 'npm:@c/d@3.1.0' },
        gitdep: { version: 'github:user/repo#abc' },
        local: { version: 'file:../local' },
      },
    });
    expect(pairs(parsePackageLock(lock))).toEqual(['bar@1.2.3', '@c/d@3.1.0']);
  });
});

describe('bun.lock', () => {
  it('reads resolved packages despite trailing commas, skipping workspace links', () => {
    const lock = `{
  "lockfileVersion": 1,
  "workspaces": { "": { "name": "app", "dependencies": { "next": "16.2.12", }, }, },
  "packages": {
    "@babel/core": ["@babel/core@7.29.7", "", { "dependencies": { "x": "^1", }, }, "sha512-a"],

    "next": ["next@16.2.12", "", {}, "sha512-b"],

    "shared": ["shared@workspace:packages/shared"],
  },
}
`;
    expect(pairs(parseBunLock(lock))).toEqual(['@babel/core@7.29.7', 'next@16.2.12']);
  });
});

describe('go.mod', () => {
  it('reads block and single-line requires, ignoring comments and replace', () => {
    const mod = `module example.com/app

go 1.22

require github.com/gin-gonic/gin v1.9.1

require (
	golang.org/x/net v0.17.0 // indirect
	// github.com/commented/out v1.0.0
	github.com/hashicorp/go-version v1.6.0
)

replace github.com/foo/bar => ../bar
`;
    expect(pairs(parseGoMod(mod))).toEqual([
      'github.com/gin-gonic/gin@v1.9.1',
      'golang.org/x/net@v0.17.0',
      'github.com/hashicorp/go-version@v1.6.0',
    ]);
  });
});

describe('python', () => {
  it('keeps only exact pins from requirements.txt', () => {
    const reqs = `# comment
Django==4.2.1
requests[security] == 2.31.0 ; python_version > "3.8"
PyYAML>=6.0
flask
-r other.txt
urllib3==1.26.5 --hash=sha256:abc
Jinja2===3.1.2  # trailing comment
`;
    expect(pairs(parseRequirements(reqs))).toEqual(['django@4.2.1', 'requests@2.31.0', 'urllib3@1.26.5', 'jinja2@3.1.2']);
  });

  it('reads pip-compile hashed pins that continue onto --hash lines', () => {
    const reqs = 'django==3.2.0 \\\n    --hash=sha256:abc \\\n    --hash=sha256:def\nflask==2.0.0\n';
    expect(pairs(parseRequirements(reqs))).toEqual(['django@3.2.0', 'flask@2.0.0']);
  });

  it('reads Pipfile.lock pins from default and develop', () => {
    const lock = JSON.stringify({
      default: { Django: { version: '==4.2.1' }, local: { path: '.' } },
      develop: { pytest: { version: '==8.0.0' } },
    });
    expect(pairs(parsePipfileLock(lock))).toEqual(['django@4.2.1', 'pytest@8.0.0']);
  });

  it('reads poetry.lock and uv.lock, skipping the local project', () => {
    const lock = `version = 1

[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "Django"
version = "4.2.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "typing_extensions"
version = "4.9.0"
`;
    expect(pairs(parsePythonTomlLock(lock))).toEqual(['django@4.2.1', 'typing-extensions@4.9.0']);
  });
});

describe('other ecosystems', () => {
  it('reads Cargo.lock, skipping workspace crates', () => {
    const lock = `version = 3

[[package]]
name = "app"
version = "0.1.0"

[[package]]
name = "openssl"
version = "0.10.55"
source = "registry+https://github.com/rust-lang/crates.io-index"
`;
    expect(pairs(parseCargoLock(lock))).toEqual(['openssl@0.10.55']);
  });

  it('reads Gemfile.lock GEM specs, stripping platforms and ignoring nested constraints', () => {
    const lock = `GIT
  remote: https://github.com/x/y.git
  specs:
    y (1.0.0)

GEM
  remote: https://rubygems.org/
  specs:
    actionpack (7.0.4)
      rack (~> 2.0)
    nokogiri (1.15.4-x86_64-linux)
    rack (2.2.6)

PLATFORMS
  x86_64-linux
`;
    expect(pairs(parseGemfileLock(lock))).toEqual(['actionpack@7.0.4', 'nokogiri@1.15.4', 'rack@2.2.6']);
    expect(new Set(parseGemfileLock(lock).map((d) => d.ecosystem))).toEqual(new Set(['gem']));
  });

  it('reads composer.lock, stripping v prefixes and skipping dev branches', () => {
    const lock = JSON.stringify({
      packages: [{ name: 'laravel/framework', version: 'v10.0.0' }, { name: 'x/y', version: 'dev-main' }],
      'packages-dev': [{ name: 'phpunit/phpunit', version: '10.1.0' }],
    });
    expect(pairs(parseComposerLock(lock))).toEqual(['laravel/framework@10.0.0', 'phpunit/phpunit@10.1.0']);
  });

  it('reads gradle.lockfile as Maven coordinates, ignoring comments, blanks, and empty=', () => {
    const lock = `# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.

com.google.guava:guava:32.1.2-jre=compileClasspath,runtimeClasspath
org.apache.logging.log4j:log4j-core:2.14.1=runtimeClasspath
org.springframework:spring-core:5.0.5.RELEASE=compileClasspath, runtimeClasspath
empty=annotationProcessor
`;
    expect(parseGradleLockfile(lock)).toEqual([
      { ecosystem: 'maven', name: 'com.google.guava:guava', version: '32.1.2-jre' },
      { ecosystem: 'maven', name: 'org.apache.logging.log4j:log4j-core', version: '2.14.1' },
      { ecosystem: 'maven', name: 'org.springframework:spring-core', version: '5.0.5.RELEASE' },
    ]);
    expect(parseGradleLockfile('# only a comment\n\nempty=\n')).toEqual([]);
    expect(parserFor('app/gradle.lockfile', lock)).toBe(parseGradleLockfile);
  });
});

describe('sbom', () => {
  it('maps purls to ecosystem-native names', () => {
    expect(fromPurl('pkg:npm/%40babel/core@7.24.0')).toEqual({ ecosystem: 'npm', name: '@babel/core', version: '7.24.0' });
    expect(fromPurl('pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar')).toEqual({
      ecosystem: 'maven',
      name: 'org.apache.logging.log4j:log4j-core',
      version: '2.14.1',
    });
    expect(fromPurl('pkg:golang/github.com/gin-gonic/gin@v1.9.1')).toEqual({
      ecosystem: 'golang',
      name: 'github.com/gin-gonic/gin',
      version: 'v1.9.1',
    });
    expect(fromPurl('pkg:npm/@babel/core@7.24.0')).toEqual({ ecosystem: 'npm', name: '@babel/core', version: '7.24.0' });
    expect(fromPurl('pkg:gem/rails@7.0.0')).toEqual({ ecosystem: 'gem', name: 'rails', version: '7.0.0' });
    expect(fromPurl('pkg:composer/laravel/framework@10.0.0')).toEqual({ ecosystem: 'composer', name: 'laravel/framework', version: '10.0.0' });
    expect(fromPurl('pkg:nuget/Newtonsoft.Json@13.0.1')).toEqual({ ecosystem: 'nuget', name: 'Newtonsoft.Json', version: '13.0.1' });
    expect(fromPurl('pkg:cargo/serde@1.0.0')).toEqual({ ecosystem: 'cargo', name: 'serde', version: '1.0.0' });
    expect(fromPurl('pkg:pypi/Django_REST.framework@3.14.0')).toEqual({ ecosystem: 'pypi', name: 'django-rest-framework', version: '3.14.0' });
    expect(fromPurl('pkg:npm/unversioned')).toBeUndefined();
    expect(fromPurl('pkg:npm/@babel/core')).toBeUndefined();
  });

  it('marks purl types outside the eight supported ecosystems as unchecked instead of guessing a name', () => {
    expect(fromPurl('pkg:deb/debian/openssl@3.0.11-1')).toEqual({
      ecosystem: 'deb',
      name: 'debian/openssl',
      version: '3.0.11-1',
      reason: 'ecosystem not supported (purl type "deb")',
    });
    expect(fromPurl('pkg:generic/zlib@1.2.13')).toMatchObject({ ecosystem: 'generic', name: 'zlib', reason: expect.stringContaining('not supported') });
    expect(fromPurl('pkg:github/org/repo@v1')).toMatchObject({ ecosystem: 'github', reason: expect.stringContaining('not supported') });
  });

  it('marks a Maven purl without a group, or with bad encoding, as unchecked', () => {
    expect(fromPurl('pkg:maven/log4j-core@2.14.1')).toMatchObject({ ecosystem: 'maven', reason: expect.stringContaining('group') });
    expect(fromPurl('pkg:npm/bad%ZZ@1.0.0')).toMatchObject({ ecosystem: 'npm', reason: 'invalid package URL encoding' });
  });

  it('reads nested CycloneDX components; ones without a purl are unchecked', () => {
    const bom = JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      components: [
        { name: 'jquery', version: '3.7.1', purl: 'pkg:npm/jquery@3.7.1' },
        { group: 'org.example', name: 'lib', version: '1.0', components: [{ name: 'inner', version: '2.0' }] },
        { name: 'no-version' },
      ],
    });
    const deps = parseSbom(bom);
    expect(pairs(deps)).toEqual(['jquery@3.7.1', 'org.example:lib@1.0', 'inner@2.0']);
    expect(deps[0]).toEqual({ ecosystem: 'npm', name: 'jquery', version: '3.7.1' });
    expect(deps.slice(1)).toEqual([
      { ecosystem: 'unknown', name: 'org.example:lib', version: '1.0', reason: expect.stringContaining('no package URL') },
      { ecosystem: 'unknown', name: 'inner', version: '2.0', reason: expect.stringContaining('no package URL') },
    ]);
  });

  it('reads SPDX packages, skipping the described root; ones without a purl are unchecked', () => {
    const bom = JSON.stringify({
      spdxVersion: 'SPDX-2.3',
      documentDescribes: ['SPDXRef-root'],
      packages: [
        { SPDXID: 'SPDXRef-root', name: 'app', versionInfo: '1.0.0' },
        {
          SPDXID: 'SPDXRef-1',
          name: 'log4j-core',
          versionInfo: '2.14.1',
          externalRefs: [{ referenceType: 'purl', referenceLocator: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1' }],
        },
        { SPDXID: 'SPDXRef-2', name: 'zlib', versionInfo: '1.2.13' },
      ],
    });
    const deps = parseSbom(bom);
    expect(pairs(deps)).toEqual(['org.apache.logging.log4j:log4j-core@2.14.1', 'zlib@1.2.13']);
    expect(deps[0]).toMatchObject({ ecosystem: 'maven' });
    expect(deps[1]).toMatchObject({ ecosystem: 'unknown', reason: expect.stringContaining('no package URL') });
  });

  it('detects SBOMs by content only for JSON files without a known lockfile name', () => {
    const bom = JSON.stringify({ bomFormat: 'CycloneDX', components: [] });
    expect(parserFor('out/sbom.json', bom)).toBe(parseSbom);
    expect(parserFor('out/other.json', '{"a":1}')).toBeUndefined();
    expect(parserFor('requirements-dev.txt', '')).toBe(parseRequirements);
  });
});
