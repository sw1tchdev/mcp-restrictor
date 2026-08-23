# Policy reference

## Minimal allowlist

Policies are YAML and currently use version `1`. The `default` value is optional and implicitly `default: deny`.

```yaml
version: 1
tools:
  allow:
    - name: read_file
  deny: []
```

This policy allows `read_file` and denies invocations that match no allow rule.

## Evaluation order

For each well-formed `tools/call`, policy evaluation is deny-first:

1. A matching deny rule denies the call.
2. Otherwise, a matching allow rule allows the call.
3. Otherwise, `default: allow` allows the call; `default: deny` denies it.

All conditions on a rule must match. An unconditional rule has no conditions and matches every invocation of its named tool.

## Discovery versus invocation

Discovery and invocation are deliberately separate. `tools/list` shows a tool when the default is allow or any allow rule names it, except an unconditional deny rule hides that tool. Conditions are not evaluated for discovery, so a discovered tool can still be denied at invocation time. Every well-formed `tools/call` is evaluated independently with its arguments, and any matching deny rule wins.

## Rule schema

```yaml
version: 1
default: deny # optional; allow or deny
tools:
  allow:
    - name: tool_name
      conditions: [] # optional
  deny: []
```

Each rule has a non-empty tool `name` and an optional `conditions` list. `tools.allow` and `tools.deny` are arrays. The schema is strict: unknown fields are invalid.

## Conditions

Each condition checks one direct, own property of the `arguments` object:

```yaml
argument: path
operator: startsWith
value: /workspace/
```

Supported operators are:

- `equals`: strict JavaScript equality against a string, number, or boolean value.
- `startsWith`: a string value and string argument whose value begins with the configured text.
- `regex`: a string value and string argument tested by a JavaScript regular expression.

Nested-property traversal is unsupported: `argument` is a direct property name, not a dotted path. Missing properties do not match. `__proto__`, `constructor`, and `prototype` are rejected as unsafe argument names.

## Examples

Unconditional deny, even with `default: allow`:

```yaml
version: 1
default: allow
tools:
  allow: []
  deny:
    - name: delete_file
```

Conditional allow:

```yaml
version: 1
default: deny
tools:
  allow:
    - name: write_file
      conditions:
        - argument: path
          operator: startsWith
          value: /workspace/
  deny: []
```

Conditional deny:

```yaml
version: 1
default: allow
tools:
  allow: []
  deny:
    - name: query
      conditions:
        - argument: statement
          operator: regex
          value: "^DROP\\b"
```

Multiple conditions form an AND. For example, a rule can require both `database: analytics` with `equals` and a `statement` matching a `regex`.

## Validation and failure behavior

Policy loading parses YAML and validates the complete policy before producing an authorizer. Version values other than `1`, unknown fields, invalid rule shapes, empty or unsafe argument names, wrong condition value types, and malformed regular expressions are rejected.

`startsWith` and `regex` require string configured values. A malformed `tools/call` is rejected by the proxy rather than authorized or forwarded. A valid but disallowed invocation receives an MCP tool-call-denied error.

## Security limitations

`startsWith` is lexical rather than path canonicalization. For filesystem security, do not treat a prefix match alone as proof that a resolved path stays within a directory.

Regex uses the ordinary JavaScript engine without a dedicated timeout. Avoid patterns whose evaluation may be expensive on attacker-controlled input.

Policy conditions inspect only direct tool arguments. They do not inspect nested objects, prompt or resource content, tool results, client-native tools, or traffic that bypasses Restrictor.
