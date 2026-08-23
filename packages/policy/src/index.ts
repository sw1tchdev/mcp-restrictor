import { readFile } from "node:fs/promises";
import { parse, stringify } from "yaml";
import { z } from "zod";

const unsafeArguments = new Set(["__proto__", "constructor", "prototype"]);

const conditionSchema = z
  .object({
    argument: z
      .string()
      .min(1)
      .refine((value) => !unsafeArguments.has(value), "unsafe argument name"),
    operator: z.enum(["equals", "startsWith", "regex"]),
    value: z.union([z.string(), z.number(), z.boolean()]),
  })
  .strict()
  .superRefine((condition, context) => {
    if (
      (condition.operator === "startsWith" || condition.operator === "regex") &&
      typeof condition.value !== "string"
    ) {
      context.addIssue({
        code: "custom",
        message: `${condition.operator} requires a string value`,
        path: ["value"],
      });
    }

    if (condition.operator === "regex" && typeof condition.value === "string") {
      try {
        new RegExp(condition.value);
      } catch {
        context.addIssue({
          code: "custom",
          message: "invalid regular expression",
          path: ["value"],
        });
      }
    }
  });

const toolRuleSchema = z
  .object({
    name: z.string().min(1),
    conditions: z.array(conditionSchema).default([]),
  })
  .strict();

const policySchema = z
  .object({
    version: z.literal(1),
    default: z.enum(["allow", "deny"]).default("deny"),
    tools: z
      .object({
        allow: z.array(toolRuleSchema).default([]),
        deny: z.array(toolRuleSchema).default([]),
      })
      .strict(),
  })
  .strict();

export type Condition = {
  argument: string;
  operator: "equals" | "startsWith" | "regex";
  value: string | number | boolean;
};
export type ToolRule = { name: string; conditions?: Condition[] };
export type Policy = {
  version: 1;
  default: "allow" | "deny";
  tools: { allow: ToolRule[]; deny: ToolRule[] };
};
export type Decision = { allowed: boolean; reason?: string };

type ParsedPolicy = z.infer<typeof policySchema>;
type ParsedToolRule = ParsedPolicy["tools"]["allow"][number];
type ParsedCondition = ParsedToolRule["conditions"][number];

export async function loadPolicy(path: string): Promise<Policy> {
  const source = await readFile(path, "utf8");
  return parsePolicy(source);
}

export function parsePolicy(source: string): Policy {
  return policySchema.parse(parse(source));
}

export function stringifyPolicy(policy: Policy): string {
  policySchema.parse(policy);
  return stringify(policy, { lineWidth: 0 });
}

export function createPolicyAuthorizer(policy: Policy) {
  const parsed = policySchema.parse(policy);

  return {
    discover(name: string): boolean {
      const denied = parsed.tools.deny.some(
        (rule) => rule.name === name && rule.conditions.length === 0,
      );

      return (
        !denied &&
        (parsed.default === "allow" || parsed.tools.allow.some((rule) => rule.name === name))
      );
    },

    authorize(name: string, arguments_: Record<string, unknown>): Decision {
      if (parsed.tools.deny.some((rule) => matches(rule, name, arguments_))) {
        return { allowed: false, reason: "explicit deny rule matched" };
      }

      if (parsed.tools.allow.some((rule) => matches(rule, name, arguments_))) {
        return { allowed: true };
      }

      return parsed.default === "allow"
        ? { allowed: true }
        : { allowed: false, reason: "no allow rule matched" };
    },
  };
}

function matches(rule: ParsedToolRule, name: string, arguments_: Record<string, unknown>): boolean {
  return (
    rule.name === name &&
    rule.conditions.every((condition) => matchesCondition(condition, arguments_))
  );
}

function matchesCondition(
  condition: ParsedCondition,
  arguments_: Record<string, unknown>,
): boolean {
  if (!Object.hasOwn(arguments_, condition.argument)) return false;

  const actual = arguments_[condition.argument];
  switch (condition.operator) {
    case "equals":
      return actual === condition.value;
    case "startsWith":
      return (
        typeof actual === "string" &&
        typeof condition.value === "string" &&
        actual.startsWith(condition.value)
      );
    case "regex":
      return (
        typeof actual === "string" &&
        typeof condition.value === "string" &&
        new RegExp(condition.value).test(actual)
      );
  }
}
