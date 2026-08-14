const fallbackAdapter = (textarea, onChange) => {
  const notify = () => onChange?.(textarea.value);
  textarea.addEventListener("input", notify);
  return {
    kind: "textarea",
    focus() {
      textarea.focus();
    },
    getValue() {
      return textarea.value;
    },
    setValue(value) {
      textarea.value = value;
      notify();
    },
  };
};

export async function createSourceEditor({
  mount,
  textarea,
  language = "python",
  onChange,
}) {
  const fallback = fallbackAdapter(textarea, onChange);

  const preferBasicEditor =
    globalThis.matchMedia?.("(max-width: 699px) and (pointer: coarse)").matches ??
    false;
  if (
    !mount ||
    !textarea ||
    typeof Worker === "undefined" ||
    preferBasicEditor
  ) {
    return fallback;
  }

  try {
    const { monaco } = await import("./assets/monaco-editor.mjs");
    const model = monaco.editor.createModel(
      textarea.value,
      language,
      monaco.Uri.parse("inmemory://itcs/source.py"),
    );
    model.updateOptions({
      insertSpaces: true,
      tabSize: 4,
      trimAutoWhitespace: true,
    });

    const editor = monaco.editor.create(mount, {
      model,
      theme: "itcs-dark",
      ariaLabel: "Python source code editor",
      automaticLayout: true,
      bracketPairColorization: { enabled: true },
      contextmenu: false,
      cursorBlinking: "smooth",
      detectIndentation: false,
      folding: true,
      fontFamily:
        '"SFMono-Regular", "Cascadia Code", "Roboto Mono", Consolas, monospace',
      fontLigatures: true,
      fontSize: 13,
      glyphMargin: false,
      guides: {
        bracketPairs: "active",
        indentation: true,
      },
      lineHeight: 22,
      lineNumbersMinChars: 3,
      minimap: { enabled: false },
      overviewRulerBorder: false,
      padding: { top: 16, bottom: 28 },
      renderLineHighlight: "line",
      renderWhitespace: "selection",
      scrollBeyondLastLine: false,
      smoothScrolling: true,
      stickyScroll: { enabled: false },
      tabSize: 4,
      wordWrap: "off",
    });

    const subscription = editor.onDidChangeModelContent(() => {
      onChange?.(editor.getValue());
    });
    mount.dataset.ready = "true";
    textarea.hidden = true;

    globalThis.addEventListener(
      "pagehide",
      () => {
        subscription.dispose();
        editor.dispose();
        model.dispose();
      },
      { once: true },
    );

    return {
      kind: "monaco",
      focus() {
        editor.focus();
      },
      getValue() {
        return editor.getValue();
      },
      setValue(value) {
        if (editor.getValue() === value) return;
        editor.setValue(value);
      },
    };
  } catch (error) {
    console.warn("Monaco failed to initialize; using textarea fallback.", error);
    return fallback;
  }
}
