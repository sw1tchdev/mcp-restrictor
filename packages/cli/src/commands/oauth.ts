import { createInterface } from "node:readline/promises";
import type { Readable, Writable } from "node:stream";
import { ConfirmationCancelled, confirmTerminal } from "../confirmation.js";
import { loginOAuthProfile, type OAuthRedirectDelivery } from "../oauth/login.js";
import {
  assertProfileId,
  readOAuthProfileSnapshot,
  writeOAuthProfile,
  type OAuthStorageOptions,
} from "../oauth/storage.js";
import { readSecretLine } from "../secret-input.js";
import { MultiSelectCancelled, selectWithTui } from "../setup/tui/multi-select.js";
import { readTextWithTui, TextInputCancelled } from "../setup/tui/text-input.js";
import { withExclusiveReadlineInput } from "../utils/terminal-input.js";

export async function runOAuthLoginCommand(
  profileId: string,
  options: {
    signal?: AbortSignal;
    readOAuthProfileSnapshot?: typeof readOAuthProfileSnapshot;
    loginOAuthProfile?: typeof loginOAuthProfile;
    writeOAuthProfile?: typeof writeOAuthProfile;
    readSecret?: (question: string) => Promise<string>;
  },
  context: {
    home: string;
    environment: NodeJS.ProcessEnv;
    input: Readable;
    output: Writable;
  },
): Promise<void> {
  assertProfileId(profileId);
  const storage: OAuthStorageOptions = {
    home: context.home,
    environment: context.environment,
  };
  const readSnapshot = options.readOAuthProfileSnapshot ?? readOAuthProfileSnapshot;
  const before = await readSnapshot(profileId, storage);
  const readline = createInterface({ input: context.input, crlfDelay: Infinity });
  const answers = readline[Symbol.asyncIterator]();
  const localController = new AbortController();
  const signal = options.signal
    ? AbortSignal.any([options.signal, localController.signal])
    : localController.signal;
  const usesTui = Boolean(
    (context.input as NodeJS.ReadStream).isTTY &&
    (context.output as NodeJS.WriteStream).isTTY &&
    typeof (context.input as NodeJS.ReadStream).setRawMode === "function",
  );
  const abortOnEnd = () => localController.abort();
  if (usesTui) {
    context.input.once("end", abortOnEnd);
    if ((context.input as NodeJS.ReadStream).readableEnded) abortOnEnd();
  }
  const ask = async (question: string): Promise<string> => {
    signal.throwIfAborted();
    context.output.write(question);
    const answer = await answers.next();
    if (answer.done) {
      localController.abort();
      throw new ConfirmationCancelled();
    }
    return answer.value.trim();
  };
  const readSecret =
    options.readSecret ??
    (async (question: string) => {
      if (usesTui) {
        try {
          return await withExclusiveReadlineInput(
            context.input as NodeJS.ReadStream,
            readline,
            () =>
              readTextWithTui({
                message: question.replace(/:\s*$/, ""),
                input: context.input as NodeJS.ReadStream,
                output: context.output as NodeJS.WriteStream,
                error: context.output as NodeJS.WriteStream,
                signal,
                secret: true,
              }),
          );
        } catch (error) {
          if (error instanceof TextInputCancelled || signal.aborted) {
            localController.abort();
            throw new ConfirmationCancelled();
          }
          throw error;
        }
      }
      context.output.write(question);
      try {
        return await readSecretLine({
          input: context.input as Parameters<typeof readSecretLine>[0]["input"],
          readline,
          signal,
          cancel: () => localController.abort(),
        });
      } finally {
        context.output.write("\n");
      }
    });

  try {
    const login = options.loginOAuthProfile ?? loginOAuthProfile;
    const profile = await login({
      input: {
        metadata: before.profile.metadata,
        clientInformation: before.profile.credentials.clientInformation,
        discoveryState: before.profile.credentials.discoveryState,
      },
      io: {
        ...(usesTui
          ? {
              selectRedirectDelivery: async (): Promise<OAuthRedirectDelivery> => {
                try {
                  const [choice] = await withExclusiveReadlineInput(
                    context.input as NodeJS.ReadStream,
                    readline,
                    () =>
                      selectWithTui({
                        message: "OAuth redirect delivery",
                        choices: ["Loopback listener", "Paste redirected URL"],
                        input: context.input as NodeJS.ReadStream,
                        output: context.output as NodeJS.WriteStream,
                        error: context.output as NodeJS.WriteStream,
                        signal,
                        required: true,
                        single: true,
                        defaultIndexes: [0],
                      }),
                  );
                  return choice === 1 ? "paste" : "listener";
                } catch (error) {
                  if (error instanceof MultiSelectCancelled || signal.aborted) {
                    localController.abort();
                    throw new ConfirmationCancelled();
                  }
                  throw error;
                }
              },
            }
          : {}),
        confirmAuthorizationServer: async (details) => {
          context.output.write(
            `OAuth authorization server: ${details.authorizationServerUrl.href}\n`,
          );
          try {
            const confirmed = await confirmTerminal({
              message: "Continue?",
              input: context.input,
              output: context.output,
              error: context.output,
              readline,
              signal,
              ask,
            });
            if (confirmed && usesTui && !options.readSecret) {
              readline.pause();
              context.input.pause();
            }
            return confirmed;
          } catch (error) {
            if (error instanceof ConfirmationCancelled) localController.abort();
            throw error;
          }
        },
        writeAuthorizationUrl: (url) => {
          context.output.write(`Open this URL to authorize:\n${url.href}\n`);
        },
        readPastedRedirect: async () =>
          new URL((await readSecret("Paste the final redirect URL: ")).trim()),
      },
      signal,
    });
    if (usesTui && !options.readSecret) {
      context.input.resume();
      await new Promise<void>((resolveTurn) => setImmediate(resolveTurn));
    }
    signal.throwIfAborted();
    if (profile.metadata.profileId !== profileId) {
      throw new Error("OAuth login returned a different profile ID");
    }
    const writeProfile = options.writeOAuthProfile ?? writeOAuthProfile;
    await writeProfile(profile, { ...storage, before: before.snapshot });
    context.output.write(`OAuth profile ${profileId} updated.\n`);
  } finally {
    context.input.removeListener("end", abortOnEnd);
    readline.close();
  }
}
