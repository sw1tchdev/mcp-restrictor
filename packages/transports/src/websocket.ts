import {
  deserializeMessage,
  type JSONRPCMessage,
  type Transport,
} from "@modelcontextprotocol/client";
import WebSocket, { type RawData } from "ws";
import { abortError, asError, MAX_MCP_MESSAGE_BYTES } from "./utils.js";

export class WebSocketClientTransport implements Transport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage) => void;

  readonly #url: URL;
  readonly #headers: Headers | undefined;
  readonly #signal: AbortSignal | undefined;
  #socket: WebSocket | undefined;
  #startPromise: Promise<void> | undefined;
  #closePromise: Promise<void> | undefined;
  #rejectStart: ((error: Error) => void) | undefined;
  #abort: (() => void) | undefined;
  #didClose = false;
  #failed = false;

  constructor(url: URL, headers?: Headers, signal?: AbortSignal) {
    this.#url = url;
    this.#headers = headers;
    this.#signal = signal;
  }

  start(): Promise<void> {
    if (this.#startPromise) return this.#startPromise;
    if (this.#didClose) return Promise.reject(new Error("WebSocket transport is closed"));

    this.#startPromise = new Promise((resolve, reject) => {
      let settled = false;
      const rejectStart = (error: Error) => {
        if (settled) return;
        settled = true;
        this.#rejectStart = undefined;
        reject(error);
      };
      this.#rejectStart = rejectStart;
      this.#abort = () => {
        rejectStart(abortError());
        this.#socket?.terminate();
      };
      this.#signal?.addEventListener("abort", this.#abort, { once: true });
      if (this.#signal?.aborted) {
        this.#abort();
        return;
      }

      let socket: WebSocket;
      try {
        socket = new WebSocket(this.#url, "mcp", {
          headers: Object.fromEntries(this.#headers ?? []),
          perMessageDeflate: false,
          followRedirects: false,
          maxPayload: MAX_MCP_MESSAGE_BYTES,
        });
      } catch (error) {
        rejectStart(asError(error));
        return;
      }
      this.#socket = socket;
      socket.on("open", () => {
        if (socket.protocol !== "mcp") {
          const error = new Error("WebSocket server did not negotiate mcp");
          rejectStart(error);
          this.#fail(error);
          return;
        }
        if (settled) return;
        settled = true;
        this.#rejectStart = undefined;
        resolve();
      });
      socket.on("message", (data, isBinary) => this.#receive(data, isBinary));
      socket.on("error", (error) => {
        rejectStart(error);
        this.onerror?.(error);
      });
      socket.on("close", () => {
        rejectStart(new Error("WebSocket closed during start"));
        this.#finishClose();
      });
    });
    return this.#startPromise;
  }

  async send(message: JSONRPCMessage): Promise<void> {
    const socket = this.#socket;
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      throw new Error("WebSocket transport is not open");
    }
    const payload = JSON.stringify(message);
    if (Buffer.byteLength(payload) > MAX_MCP_MESSAGE_BYTES) {
      throw new Error("WebSocket payload exceeds 10 MiB");
    }
    await new Promise<void>((resolve, reject) => {
      socket.send(payload, (error) => (error ? reject(error) : resolve()));
    });
  }

  close(): Promise<void> {
    if (this.#closePromise) return this.#closePromise;
    this.#closePromise = this.#close();
    return this.#closePromise;
  }

  async #close(): Promise<void> {
    this.#clearAbort();
    this.#rejectStart?.(new Error("WebSocket transport closed"));
    const socket = this.#socket;
    if (!socket || socket.readyState === WebSocket.CLOSED) {
      this.#finishClose();
      return;
    }
    await new Promise<void>((resolve) => {
      socket.removeAllListeners();
      socket.once("error", () => {});
      socket.once("close", () => resolve());
      if (socket.readyState === WebSocket.CONNECTING) socket.terminate();
      else socket.close();
    });
    this.#finishClose();
  }

  #receive(data: RawData, isBinary: boolean): void {
    if (this.#failed) return;
    try {
      if (isBinary) throw new Error("Binary WebSocket messages are not supported");
      const bytes = flatten(data);
      const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      const message = deserializeMessage(text);
      this.onmessage?.(message);
    } catch (error) {
      this.#fail(asError(error));
    }
  }

  #fail(error: Error): void {
    this.#failed = true;
    this.#rejectStart?.(error);
    const socket = this.#socket;
    if (socket && socket.readyState < WebSocket.CLOSING) socket.close(1002);
    this.onerror?.(error);
  }

  #finishClose(): void {
    this.#clearAbort();
    this.#socket = undefined;
    if (this.#didClose) return;
    this.#didClose = true;
    this.onclose?.();
  }

  #clearAbort(): void {
    if (!this.#abort) return;
    this.#signal?.removeEventListener("abort", this.#abort);
    this.#abort = undefined;
  }
}

function flatten(data: RawData): Uint8Array {
  if (!Array.isArray(data)) {
    const bytes =
      data instanceof ArrayBuffer
        ? new Uint8Array(data)
        : new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    if (bytes.byteLength > MAX_MCP_MESSAGE_BYTES) throw payloadError();
    return bytes;
  }
  let length = 0;
  for (const part of data) {
    length += part.byteLength;
    if (length > MAX_MCP_MESSAGE_BYTES) throw payloadError();
  }
  return Buffer.concat(data, length);
}

function payloadError(): Error {
  return new Error("WebSocket payload exceeds 10 MiB");
}
