import * as core from '@actions/core';
import { readInputs, run } from './main.ts';

try {
  await run(readInputs());
} catch (error) {
  core.setFailed(error instanceof Error ? error.message : String(error));
}
