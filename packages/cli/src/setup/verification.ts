import { isDeepStrictEqual } from "node:util";
import type { Writable } from "node:stream";
import { discoverToolNames, type UpstreamConfig } from "@mcp-restrictor/transports";
import {
  oauthProfilePath,
  readOAuthProfileSnapshot,
  type OAuthProfile,
  type OAuthStorageOptions,
} from "../oauth/storage.js";
import { isAbort } from "./discovery.js";
import type { AcceptInstalledUpdate } from "./transaction.js";

export type VerificationSelection = {
  tools: readonly string[];
  verificationUpstream: UpstreamConfig;
  oauthProfile?: OAuthProfile;
  storage?: OAuthStorageOptions;
  context: string;
};

export async function verifySelections(
  selections: readonly VerificationSelection[],
  acceptInstalledUpdate: AcceptInstalledUpdate,
  signal: AbortSignal,
  stderr: Writable,
): Promise<void> {
  for (const selection of selections) {
    await verifySelection(selection, acceptInstalledUpdate, signal, stderr);
  }
}

export async function verifySelection(
  selection: VerificationSelection,
  acceptInstalledUpdate: AcceptInstalledUpdate,
  signal: AbortSignal,
  stderr: Writable,
): Promise<void> {
  let actual: string[] | undefined;
  let discoveryFailure: unknown;
  try {
    actual = await discoverToolNames(selection.verificationUpstream, { signal, stderr });
  } catch (error) {
    discoveryFailure = isAbort(error, signal)
      ? error
      : new Error(`Wrapper verification failed for ${selection.context}`);
  }
  let acceptanceFailure: unknown;
  if (selection.oauthProfile && selection.storage) {
    try {
      const profile = selection.oauthProfile;
      await acceptInstalledUpdate(
        oauthProfilePath(selection.storage.home!, profile.metadata.profileId),
        async (snapshot) => {
          const current = await readOAuthProfileSnapshot(
            profile.metadata.profileId,
            selection.storage,
          );
          if (
            current.snapshot.path !== snapshot.path ||
            current.snapshot.dev !== snapshot.dev ||
            current.snapshot.ino !== snapshot.ino ||
            current.snapshot.content !== snapshot.content ||
            !sameOAuthProfileIdentity(profile, current.profile)
          )
            throw new Error("OAuth profile changed outside token rotation");
        },
      );
    } catch (error) {
      acceptanceFailure = error;
    }
  }
  if (discoveryFailure !== undefined && acceptanceFailure !== undefined) {
    throw new AggregateError(
      [discoveryFailure, acceptanceFailure],
      "Wrapper verification and OAuth profile acceptance failed",
    );
  }
  if (discoveryFailure !== undefined) throw discoveryFailure;
  if (acceptanceFailure !== undefined) throw acceptanceFailure;
  if (!actual || !sameStrings(actual, selection.tools)) {
    throw new Error(`Wrapper verification returned unexpected tools for ${selection.context}`);
  }
}

function sameOAuthProfileIdentity(left: OAuthProfile, right: OAuthProfile): boolean {
  return (
    isDeepStrictEqual(left.metadata, right.metadata) &&
    isDeepStrictEqual(left.credentials.clientInformation, right.credentials.clientInformation) &&
    isDeepStrictEqual(left.credentials.discoveryState, right.credentials.discoveryState)
  );
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}
