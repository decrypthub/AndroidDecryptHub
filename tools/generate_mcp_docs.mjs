// Source-registry documentation. Pure imports; never initialize a Host or discover devices.
import {readFileSync,writeFileSync} from 'node:fs';
process.env.ADH_SKIP_ARTIFACT_LOAD='1';
delete process.env.ADH_DATA_DIR;delete process.env.ADH_CAPTURES_DIR;
const {MCP_TOOLS}=await import('../daemon/src/mcp.ts');
const clean=value=>String(value).replace(/\|/g,'\\|').replace(/\r?\n/g,' ');
const header=`# ADH MCP Tools

Generated from the source registry (${MCP_TOOLS.length} tools). Endpoint: \`POST /mcp\` (JSON-RPC 2.0).

Writes require \`_operation\` state/control versions: [P1_OPERATIONS.md](P1_OPERATIONS.md). Human workbench, task CAS, intent lookup and effect metadata: [P2_WORKBENCH.md](P2_WORKBENCH.md). Read queries remain compatible; unversioned writes fail closed.

Verified installation identities, device capabilities and USB/ADB RPC: [P3_DEVICE_DOMAIN.md](P3_DEVICE_DOMAIN.md). Legacy target sessions remain unassociated; LAN/TLS are not implemented.

| Tool | Description | Args |
|---|---|---|
`;
const doc=header+MCP_TOOLS.map(t=>`| \`${t.name}\` | ${clean(t.description)} | ${Object.keys(t.inputSchema.properties).join(', ')} |`).join('\n')+'\n';
const destination=new URL('../docs/mcp-tools.md',import.meta.url);
if(process.argv.includes('--check')){if(readFileSync(destination,'utf8')!==doc)throw Error('MCP docs out of date: node tools/generate_mcp_docs.mjs');}
else writeFileSync(destination,doc);
console.log(`MCP documentation: ${MCP_TOOLS.length} tools; ${process.argv.includes('--check')?'PASS':'generated'}`);
