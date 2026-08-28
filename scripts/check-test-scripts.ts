import { file } from 'bun';
import { join } from 'node:path';

/**
 * Fails if a workspace ships a `test` script that cannot fail.
 *
 * `op-verifier` carried `"test": "echo hardhat test"` for a long time. It printed a string,
 * exited 0, and read as a passing suite, so nobody noticed its ten tests were never running.
 * This guard makes that class of mistake break the build instead of hiding in it.
 */

const root = join(import.meta.dir, '..');

// A test script whose whole job is to print something, or to succeed unconditionally.
const NO_OP_PATTERNS = [/^echo\b/, /^exit\s+0$/, /^true$/, /^:$/];

const packageJson = await file(join(root, 'package.json')).json();
const workspaces = packageJson.workspaces as string[];

const offenders: string[] = [];

for (const workspace of workspaces) {
  const manifestPath = join(root, workspace, 'package.json');
  const manifest = await file(manifestPath).json();
  const script = manifest.scripts?.test;

  if (typeof script !== 'string') continue;

  const normalised = script.trim();
  if (NO_OP_PATTERNS.some((pattern) => pattern.test(normalised))) {
    offenders.push(`  ${workspace}: "test": "${script}"`);
  }
}

if (offenders.length > 0) {
  console.error(
    'These workspaces have a `test` script that always succeeds without running anything:\n'
  );
  console.error(offenders.join('\n'));
  console.error(
    '\nReplace it with a real test command, or remove it so the workspace is honestly untested.'
  );
  process.exit(1);
}

console.log(`Checked ${workspaces.length} workspaces; no no-op test scripts.`);
