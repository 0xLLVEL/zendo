<script>
  import { onMount } from "svelte";
  import { EditorState, StateEffect, StateField, Compartment, Prec } from "@codemirror/state";
  import { EditorView, keymap, Decoration, drawSelection } from "@codemirror/view";
  import { basicSetup } from "codemirror";
  import { indentWithTab } from "@codemirror/commands";
  import { HighlightStyle, syntaxHighlighting } from "@codemirror/language";
  import { tags as t } from "@lezer/highlight";
  import { luau } from "../lib/luau.js";

  let { value = "", onrun, onsave, onchange, oncursor, errorLine = 0, font = 13, wrap = false } = $props();

  let host;
  let view;

  const faceComp = new Compartment();
  const wrapComp = new Compartment();

  const setError = StateEffect.define();

  const errorField = StateField.define({
    create: () => Decoration.none,
    update(deco, tr) {
      let next = deco.map(tr.changes);
      for (const effect of tr.effects) {
        if (!effect.is(setError)) continue;
        if (!effect.value) {
          next = Decoration.none;
          continue;
        }
        const doc = tr.state.doc;
        const n = Math.min(Math.max(1, effect.value), doc.lines);
        next = Decoration.set([
          Decoration.line({ class: "cm-errline" }).range(doc.line(n).from),
        ]);
      }
      return next;
    },
    provide: (f) => EditorView.decorations.from(f),
  });

  const highlight = HighlightStyle.define([
    { tag: t.keyword, color: "#9db0ff" },
    { tag: [t.standard(t.name), t.standard(t.variableName)], color: "#c3cbdd" },
    { tag: t.typeName, color: "#8fa3d8" },
    { tag: t.string, color: "#8fe3c0" },
    { tag: t.number, color: "#ffcf8a" },
    { tag: t.bool, color: "#ff9ab8" },
    { tag: t.null, color: "#ff9ab8" },
    { tag: t.comment, color: "#5c6684", fontStyle: "italic" },
    { tag: [t.function(t.variableName), t.function(t.propertyName)], color: "#eef2ff" },
    { tag: [t.operator, t.punctuation], color: "#7c88a8" },
    { tag: t.propertyName, color: "#dbe2f2" },
  ]);

  const face = (size) =>
    EditorView.theme(
      {
        "&": { height: "100%", backgroundColor: "transparent", color: "#e4e9f5" },
        ".cm-scroller": {
          fontFamily: "var(--font-mono)",
          fontSize: `${size}px`,
          lineHeight: "1.65",
          overflow: "auto",
        },
        ".cm-content": { padding: "12px 0", caretColor: "var(--accent)" },
        ".cm-line": { padding: "0 18px 0 6px" },
        ".cm-gutters": {
          backgroundColor: "transparent",
          color: "#46506b",
          border: "none",
          paddingLeft: "10px",
        },
        ".cm-lineNumbers .cm-gutterElement": {
          padding: "0 12px 0 4px",
          minWidth: "40px",
          fontSize: `${Math.max(10, size - 1)}px`,
        },
        ".cm-activeLine": { backgroundColor: "rgb(255 255 255 / 0.025)" },
        ".cm-activeLineGutter": { backgroundColor: "transparent", color: "var(--accent)" },
        "&.cm-focused .cm-selectionBackground, .cm-selectionBackground": {
          backgroundColor: "color-mix(in srgb, var(--accent) 26%, transparent)",
        },
        ".cm-cursor, .cm-dropCursor": {
          borderLeftColor: "var(--accent)",
          borderLeftWidth: "2px",
        },
        ".cm-matchingBracket, &.cm-focused .cm-matchingBracket": {
          backgroundColor: "color-mix(in srgb, var(--accent) 18%, transparent)",
          outline: "1px solid color-mix(in srgb, var(--accent) 40%, transparent)",
        },
        ".cm-panels": { backgroundColor: "#10131e", color: "#e4e9f5" },
        ".cm-panels.cm-panels-bottom": { borderTop: "1px solid rgb(255 255 255 / 0.08)" },
        ".cm-searchMatch": { backgroundColor: "color-mix(in srgb, var(--accent) 22%, transparent)" },
        ".cm-searchMatch.cm-searchMatch-selected": {
          backgroundColor: "color-mix(in srgb, var(--accent) 40%, transparent)",
        },
        ".cm-tooltip": {
          backgroundColor: "#10131e",
          border: "1px solid rgb(255 255 255 / 0.1)",
          borderRadius: "8px",
        },
        ".cm-errline": {
          backgroundColor: "color-mix(in srgb, var(--color-danger) 12%, transparent)",
          boxShadow: "inset 2px 0 0 var(--color-danger)",
        },
      },
      { dark: true }
    );

  const wrapping = (on) => (on ? EditorView.lineWrapping : []);

  onMount(() => {
    view = new EditorView({
      parent: host,
      state: EditorState.create({
        doc: value,
        extensions: [
          basicSetup,
          drawSelection(),
          luau,
          errorField,
          faceComp.of(face(font)),
          wrapComp.of(wrapping(wrap)),
          syntaxHighlighting(highlight),
          Prec.high(
            keymap.of([
              { key: "Mod-Enter", run: () => (onrun?.(), true) },
              { key: "Mod-s", run: () => (onsave?.(), true) },
              indentWithTab,
            ])
          ),
          EditorView.updateListener.of((u) => {
            if (u.docChanged) onchange?.(u.state.doc.toString());
            if (u.docChanged || u.selectionSet) {
              const head = u.state.selection.main.head;
              const line = u.state.doc.lineAt(head);
              oncursor?.(line.number, head - line.from + 1);
            }
          }),
        ],
      }),
    });

    view.focus();
    return () => {
      view.destroy();
      view = null;
    };
  });

  // The document is owned by the tab model; only push when they differ, or every
  // keystroke would round-trip through a dispatch.
  $effect(() => {
    if (!view) return;
    if (value !== view.state.doc.toString()) {
      view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: value } });
    }
  });

  $effect(() => {
    if (!view) return;
    view.dispatch({ effects: faceComp.reconfigure(face(font)) });
  });

  $effect(() => {
    if (!view) return;
    view.dispatch({ effects: wrapComp.reconfigure(wrapping(wrap)) });
  });

  $effect(() => {
    if (!view) return;
    view.dispatch({ effects: setError.of(errorLine || 0) });
    if (errorLine > 0) {
      const doc = view.state.doc;
      const line = doc.line(Math.min(errorLine, doc.lines));
      view.dispatch({ effects: EditorView.scrollIntoView(line.from, { y: "center" }) });
    }
  });
</script>

<div class="cm-host" bind:this={host}></div>
