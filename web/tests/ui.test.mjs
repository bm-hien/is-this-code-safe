import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";
import test from "node:test";

import { createSourceEditor } from "../source-editor.mjs";

const read = (path) => readFile(new URL(path, import.meta.url), "utf8");

test("source editor retains an operational textarea fallback", async () => {
  let focused = false;
  let inputListener = null;
  const changes = [];
  const textarea = {
    value: "",
    addEventListener(name, listener) {
      if (name === "input") inputListener = listener;
    },
    focus() {
      focused = true;
    },
  };

  const editor = await createSourceEditor({
    mount: null,
    textarea,
    onChange(value) {
      changes.push(value);
    },
  });

  assert.equal(editor.kind, "textarea");
  editor.setValue("print('safe')\n");
  editor.focus();

  assert.equal(editor.getValue(), "print('safe')\n");
  assert.deepEqual(changes, ["print('safe')\n"]);
  assert.equal(focused, true);
  assert.equal(typeof inputListener, "function");
});

test("page wires a local Monaco bundle and same-origin worker policy", async () => {
  const html = await read("../index.html");
  const app = await read("../app.mjs");
  const adapter = await read("../source-editor.mjs");

  assert.match(html, /id="source-editor" class="monaco-editor-host"/);
  assert.match(html, /assets\/monaco-editor\.css/);
  assert.match(html, /worker-src 'self'/);
  assert.doesNotMatch(html, /https?:\/\//);
  assert.match(app, /void createSourceEditor/);
  assert.doesNotMatch(app, /await createSourceEditor/);
  assert.doesNotMatch(app, /gated off/);
  assert.match(app, /capability floor is never reduced/);
  assert.match(app, /abstained/);
  assert.match(app, /probability shown only for audit/);
  assert.match(html, /id="purpose-title"/);
  assert.match(html, /Capability score/);
  assert.match(adapter, /import\("\.\/assets\/monaco-editor\.mjs"\)/);
  assert.match(adapter, /kind: "textarea"/);
  assert.match(adapter, /kind: "monaco"/);
});

test("committed Monaco assets are present, patched, and non-empty", async () => {
  const editorUrl = new URL("../assets/monaco-editor.mjs", import.meta.url);
  const editor = await stat(editorUrl);
  const worker = await stat(
    new URL("../assets/monaco-worker.mjs", import.meta.url),
  );
  const css = await stat(
    new URL("../assets/monaco-editor.css", import.meta.url),
  );

  const editorBundle = await readFile(editorUrl, "utf8");
  assert.ok(editor.size > 100_000);
  assert.ok(worker.size > 50_000);
  assert.ok(css.size > 10_000);
  assert.match(editorBundle, /DOMPurify 3\.4\.13/);
  assert.doesNotMatch(editorBundle, /DOMPurify 3\.4\.8/);
});
