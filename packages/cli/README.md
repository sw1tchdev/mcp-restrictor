# @mcp-restrictor/cli

The cross-client MCP proxy and interactive setup boundary: it restricts MCP
traffic that traverses the configured wrapper, not client-native tools.

Install with Node.js 22 or newer:

```bash
npm install --global @mcp-restrictor/cli
mcp-restrictor setup
```

Run setup from the project you intend to configure so it derives the correct
project root.

Requires Node.js 22+. Entry points are the `mcp-restrictor` executable and
`@mcp-restrictor/cli/client-adapter`; this project does not yet document a
stable embedding SDK contract.

Read the [root README](../../README.md), [setup guide](../../docs/setup.md),
[CLI reference](../../docs/cli.md), [OAuth guide](../../docs/oauth.md), and
[security model](../../SECURITY.md).
