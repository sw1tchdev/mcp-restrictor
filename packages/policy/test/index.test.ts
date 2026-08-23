import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "vitest";
import {
  createPolicyAuthorizer,
  loadPolicy,
  parsePolicy,
  stringifyPolicy,
  type Policy,
} from "../src/index.ts";

const policy: Policy = {
  version: 1,
  default: "deny",
  tools: {
    allow: [
      { name: "read_file" },
      {
        name: "write_file",
        conditions: [
          {
            argument: "path",
            operator: "startsWith",
            value: "/workspace/",
          },
        ],
      },
      {
        name: "query",
        conditions: [
          { argument: "database", operator: "equals", value: "analytics" },
          { argument: "statement", operator: "regex", value: "^SELECT\\b" },
        ],
      },
    ],
    deny: [{ name: "delete_file" }],
  },
};

describe("tool policy", () => {
  test("allows only matching allow rules when the default is deny", () => {
    const authorizer = createPolicyAuthorizer(policy);

    expect(authorizer.authorize("read_file", {})).toEqual({ allowed: true });
    expect(authorizer.authorize("write_file", { path: "/workspace/a.txt" })).toEqual({
      allowed: true,
    });
    expect(authorizer.authorize("write_file", { path: "/etc/passwd" })).toMatchObject({
      allowed: false,
    });
    expect(authorizer.authorize("unknown", {})).toMatchObject({ allowed: false });
  });

  test("requires every condition in a rule to match", () => {
    const authorizer = createPolicyAuthorizer(policy);

    expect(
      authorizer.authorize("query", {
        database: "analytics",
        statement: "SELECT value FROM metrics",
      }),
    ).toEqual({ allowed: true });
    expect(
      authorizer.authorize("query", {
        database: "analytics",
        statement: "DELETE FROM metrics",
      }),
    ).toMatchObject({ allowed: false });
  });

  test("an explicit deny wins and hides an unconditionally denied tool", () => {
    const authorizer = createPolicyAuthorizer({
      ...policy,
      tools: {
        allow: [...policy.tools.allow, { name: "delete_file" }],
        deny: policy.tools.deny,
      },
    });

    expect(authorizer.authorize("delete_file", {})).toMatchObject({
      allowed: false,
    });
    expect(authorizer.discover("read_file")).toBe(true);
    expect(authorizer.discover("write_file")).toBe(true);
    expect(authorizer.discover("delete_file")).toBe(false);
    expect(authorizer.discover("unknown")).toBe(false);
  });
});

describe("loadPolicy", () => {
  test("loads a valid YAML policy", async () => {
    const loaded = await withPolicyFile(`
version: 1
default: deny
tools:
  allow:
    - name: read_file
  deny: []
`);

    expect(loaded).toEqual({
      version: 1,
      default: "deny",
      tools: { allow: [{ name: "read_file", conditions: [] }], deny: [] },
    });
  });

  test.each([
    ["unknown keys", `version: 1\ndefault: deny\ntools: { allow: [], deny: [] }\nextra: true`],
    [
      "malformed regular expressions",
      `version: 1\ndefault: deny\ntools:\n  allow:\n    - name: query\n      conditions:\n        - { argument: statement, operator: regex, value: '[' }\n  deny: []`,
    ],
    [
      "unsafe property names",
      `version: 1\ndefault: deny\ntools:\n  allow:\n    - name: write_file\n      conditions:\n        - { argument: __proto__, operator: equals, value: x }\n  deny: []`,
    ],
  ])("rejects %s", async (_name, yaml) => {
    await expect(withPolicyFile(yaml)).rejects.toThrow();
  });
});

describe("parsePolicy", () => {
  test("parses a valid YAML policy source", () => {
    expect(
      parsePolicy(
        "version: 1\ndefault: deny\ntools:\n  allow:\n    - name: read_file\n  deny: []\n",
      ),
    ).toEqual({
      version: 1,
      default: "deny",
      tools: { allow: [{ name: "read_file", conditions: [] }], deny: [] },
    });
  });

  test("rejects an invalid YAML policy source", () => {
    expect(() => parsePolicy("version: 2\ntools: { allow: [], deny: [] }\n")).toThrow();
  });
});

describe("stringifyPolicy", () => {
  test("serializes validated rules without defaulted conditions", () => {
    expect(
      stringifyPolicy({
        version: 1,
        default: "deny",
        tools: { allow: [{ name: "read_file" }], deny: [] },
      }),
    ).toBe("version: 1\ndefault: deny\ntools:\n  allow:\n    - name: read_file\n  deny: []\n");
  });
});

async function withPolicyFile(yaml: string): Promise<Policy> {
  const directory = await mkdtemp(join(tmpdir(), "mcp-restrictor-policy-"));
  const path = join(directory, "policy.yaml");

  try {
    await writeFile(path, yaml, "utf8");
    return await loadPolicy(path);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}
