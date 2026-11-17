import {readFileSync} from 'node:fs';

// Resolve relative to this module, never the operator's current directory or state root.
export const HOST_VERSION: string = JSON.parse(readFileSync(new URL('../package.json',import.meta.url),'utf8')).version;
