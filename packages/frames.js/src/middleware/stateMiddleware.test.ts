/* eslint-disable no-console -- we expect the usage of console.log */
import { createHmac } from "node:crypto";
import type { FramesContext } from "../core/types";
import { stateMiddleware, InvalidStateSignatureError } from "./stateMiddleware";

function createSignature(state: any, secret: string): string {
  return createHmac("sha256", secret)
    .update(JSON.stringify(state))
    .digest("hex");
}

describe("stateMiddleware", () => {
  let consoleWarnSpy: jest.SpyInstance;

  beforeAll(() => {
    consoleWarnSpy = jest.spyOn(console, "warn");
  });

  beforeEach(() => {
    consoleWarnSpy.mockReset();
  });

  it("decodes JSON state from frame message and assigns it to ctx", async () => {
    const state = { foo: "bar" };
    const ctx = {
      message: { state: JSON.stringify(state) },
      initialState: {},
      request: new Request("http://localhost", { method: "POST" }),
    };
    const mw = stateMiddleware();
    const next = jest.fn();

    await mw(ctx as unknown as FramesContext, next);

    expect(next).toHaveBeenCalledWith({ state });
  });

  it("uses initial state and warns user if JSON decode failed", async () => {
    const state = { foo: "bar" };
    const ctx = {
      message: { state },
      initialState: { initial: true },
      request: new Request("http://localhost", { method: "POST" }),
    };
    const mw = stateMiddleware();
    const next = jest.fn();

    expect(consoleWarnSpy).not.toHaveBeenCalled();

    await mw(ctx as unknown as FramesContext, next);

    expect(consoleWarnSpy).toHaveBeenCalledWith(
      expect.stringContaining("Failed to parse state from frame message")
    );

    expect(next).toHaveBeenCalledWith({ state: { initial: true } });
  });

  it("uses initial state if there is no message", async () => {
    const ctx = {
      initialState: { initial: true },
      request: new Request("http://localhost", { method: "POST" }),
    };
    const mw = stateMiddleware();
    const next = jest.fn();

    await mw(ctx as unknown as FramesContext, next);

    expect(next).toHaveBeenCalledWith({ state: { initial: true } });
  });

  it("includes previous state in the result if it is not present", async () => {
    const state = { foo: "bar" };
    const ctx = {
      message: { state: JSON.stringify(state) },
      initialState: {},
      request: new Request("http://localhost", { method: "POST" }),
    };
    const mw = stateMiddleware();
    const next = jest.fn().mockReturnValue({ image: "/test" });

    const result = await mw(ctx as unknown as FramesContext, next);

    expect(result).toEqual({ image: "/test", state: JSON.stringify(state) });
  });

  it("warns if state is returned but we are on initial frame", async () => {
    const ctx = {
      initialState: {},
      request: new Request("http://localhost", { method: "GET" }),
    };
    const mw = stateMiddleware();
    const next = jest
      .fn()
      .mockReturnValue({ image: "/test", state: { foo: "bar" } });

    expect(consoleWarnSpy).not.toHaveBeenCalled();

    await mw(ctx as unknown as FramesContext, next);

    expect(consoleWarnSpy).toHaveBeenCalledWith(
      expect.stringContaining("State is not supported on initial request")
    );
  });

  describe("stateSigningSecret", () => {
    it("signs state with provided secret", async () => {
      const state = { foo: "bar" };
      const ctx = {
        initialState: {},
        stateSigningSecret: "test",
        request: new Request("http://localhost", { method: "POST" }),
      };

      const mw = stateMiddleware();
      const next = jest.fn().mockResolvedValue({ image: "/test", state });

      const result = await mw(ctx as unknown as FramesContext, next);

      expect(result).toMatchObject({
        image: "/test",
        state: JSON.stringify({
          data: state,
          __sig: createSignature(state, "test"),
        }),
      });
    });

    it("throws an error if state signature verification failed", async () => {
      const state = { foo: "bar" };
      const ctx = {
        message: {
          state: JSON.stringify({
            data: state,
            __sig: createSignature(state, "test2"),
          }),
        },
        initialState: {},
        stateSigningSecret: "test1",
        request: new Request("http://localhost", { method: "POST" }),
      };

      const mw = stateMiddleware();
      const next = jest.fn().mockResolvedValue({ image: "/test", state });

      await expect(mw(ctx as unknown as FramesContext, next)).rejects.toThrow(
        InvalidStateSignatureError
      );
    });

    it("warns that state is signed and uses the state if secret is not provided", async () => {
      const state = { foo: "bar" };
      const ctx = {
        message: {
          state: JSON.stringify({
            data: state,
            __sig: createSignature(state, "test"),
          }),
        },
        initialState: { initial: true },
        request: new Request("http://localhost", { method: "POST" }),
      };

      const mw = stateMiddleware();
      const next = jest.fn().mockResolvedValue({ image: "/test", state });

      await mw(ctx as unknown as FramesContext, next);

      expect(consoleWarnSpy).toHaveBeenCalledWith(
        expect.stringContaining("State is signed but no secret is provided")
      );

      expect(next).toHaveBeenCalledWith({
        state,
      });
    });

    it("uses signed state if the secret matches", async () => {
      const state = { foo: "bar" };
      const ctx = {
        message: {
          state: JSON.stringify({
            data: state,
            __sig: createSignature(state, "test"),
          }),
        },
        initialState: { initial: true },
        stateSigningSecret: "test",
        request: new Request("http://localhost", { method: "POST" }),
      };

      const mw = stateMiddleware();
      const next = jest.fn().mockResolvedValue({ image: "/test", state });

      await mw(ctx as unknown as FramesContext, next);

      expect(next).toHaveBeenCalledWith({
        state,
      });
    });
  });
});
