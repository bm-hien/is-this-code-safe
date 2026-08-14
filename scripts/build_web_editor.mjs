import { mkdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { build } from "esbuild";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const assets = path.join(root, "web", "assets");
const monacoSanitizer =
  "/monaco-editor/esm/vs/base/browser/domSanitize.js";
const patchedDomPurify = path.join(
  root,
  "node_modules",
  "dompurify",
  "dist",
  "purify.es.mjs",
);

await mkdir(assets, { recursive: true });

const patchedSanitizerPlugin = {
  name: "patched-monaco-dompurify",
  setup(context) {
    context.onResolve(
      { filter: /^\.\/dompurify\/dompurify\.js$/ },
      (args) =>
        args.importer.endsWith(monacoSanitizer)
          ? { path: patchedDomPurify }
          : null,
    );
  },
};

const shared = {
  absWorkingDir: root,
  bundle: true,
  format: "esm",
  legalComments: "eof",
  minify: true,
  platform: "browser",
  plugins: [patchedSanitizerPlugin],
  target: ["es2022"],
};

await build({
  ...shared,
  entryPoints: ["scripts/monaco_editor_entry.mjs"],
  loader: {
    ".ttf": "dataurl",
  },
  outfile: "web/assets/monaco-editor.mjs",
});

await build({
  ...shared,
  entryPoints: ["scripts/monaco_editor_worker.mjs"],
  outfile: "web/assets/monaco-worker.mjs",
});

const editorBundle = await readFile(
  path.join(assets, "monaco-editor.mjs"),
  "utf8",
);
if (
  editorBundle.includes("DOMPurify 3.4.8") ||
  !editorBundle.includes("DOMPurify 3.4.13")
) {
  throw new Error("Monaco bundle did not use the pinned DOMPurify 3.4.13.");
}

console.log("Built locally bundled Monaco editor assets in web/assets/.");
