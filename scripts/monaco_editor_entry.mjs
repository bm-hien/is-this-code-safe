import * as monaco from "monaco-editor/editor";
import "monaco-editor/features/bracketMatching/register";
import "monaco-editor/features/codeEditor/register";
import "monaco-editor/features/comment/register";
import "monaco-editor/features/cursorUndo/register";
import "monaco-editor/features/find/register";
import "monaco-editor/features/folding/register";
import "monaco-editor/features/indentation/register";
import "monaco-editor/features/lineSelection/register";
import "monaco-editor/features/linesOperations/register";
import "monaco-editor/features/multicursor/register";
import "monaco-editor/features/smartSelect/register";
import "monaco-editor/features/toggleTabFocusMode/register";
import "monaco-editor/features/tokenization/register";
import "monaco-editor/features/unusualLineTerminators/register";
import "monaco-editor/features/wordOperations/register";
import "monaco-editor/features/wordPartOperations/register";
import "monaco-editor/languages/definitions/python/register";

globalThis.MonacoEnvironment = {
  getWorker() {
    return new Worker(new URL("./monaco-worker.mjs", import.meta.url), {
      name: "itcs-monaco-editor",
      type: "module",
    });
  },
};

monaco.editor.defineTheme("itcs-dark", {
  base: "vs-dark",
  inherit: true,
  rules: [
    { token: "comment", foreground: "69877C", fontStyle: "italic" },
    { token: "keyword", foreground: "74F7BA" },
    { token: "number", foreground: "F5D36F" },
    { token: "string", foreground: "B8E994" },
    { token: "type.identifier", foreground: "77BAFF" },
  ],
  colors: {
    "editor.background": "#07110E",
    "editor.foreground": "#D9E9E3",
    "editorCursor.foreground": "#74F7BA",
    "editor.lineHighlightBackground": "#0D1D18",
    "editorLineNumber.foreground": "#536B62",
    "editorLineNumber.activeForeground": "#A9C2B8",
    "editor.selectionBackground": "#245A46",
    "editor.inactiveSelectionBackground": "#183E31",
    "editorIndentGuide.background1": "#183027",
    "editorIndentGuide.activeBackground1": "#355B4D",
    "editorBracketMatch.background": "#1A4A38",
    "editorBracketMatch.border": "#74F7BA",
    "editorGutter.background": "#07110E",
    "editorWidget.background": "#0C1714",
    "editorWidget.border": "#38554B",
    "input.background": "#07110E",
    "input.border": "#38554B",
    "focusBorder": "#74F7BA",
    "scrollbarSlider.background": "#38554B88",
    "scrollbarSlider.hoverBackground": "#4B7264AA",
    "scrollbarSlider.activeBackground": "#74F7BABB",
  },
});

export { monaco };
