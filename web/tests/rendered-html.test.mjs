import assert from "node:assert/strict";
import test from "node:test";

async function render(pathname = "/") {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}-${pathname}`);
  const { default: worker } = await import(workerUrl.href);

  return worker.fetch(
    new Request(`http://localhost${pathname}`, {
      headers: { accept: "text/html" },
    }),
    {
      ASSETS: {
        fetch: async () => new Response("Not found", { status: 404 }),
      },
    },
    {
      waitUntil() {},
      passThroughOnException() {},
    },
  );
}

test("renders the artifact-backed dataset overview", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.match(html, /C-BAE Results/);
  assert.match(html, /Semantic recovery/);
  assert.match(html, /Bedrock Server 1\.21\.0\.03/);
  assert.match(html, /Minecraft China Client 1\.16\.201/);
  assert.doesNotMatch(html, /codex-preview|react-loading-skeleton/i);
});

test("renders a binary audit route", async () => {
  const response = await render("/runs/ida-gpt56-high-bedrock-20260804/");
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.match(html, /Inspect the 100 functions the model chose/);
  assert.match(html, /Function recovery evaluation/);
  assert.match(html, /439,952/);
  assert.match(html, /deflateInit_/);
});
