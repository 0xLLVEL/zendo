import { StreamLanguage } from "@codemirror/language";

const KEYWORDS = new Set(
  ("and break continue do else elseif end export false for function if in local nil not " +
    "or repeat return then true type until while").split(" ")
);

const BUILTINS = new Set(
  ("game workspace script shared plugin task print warn error assert pcall xpcall select " +
    "type typeof tostring tonumber pairs ipairs next rawget rawset rawequal rawlen " +
    "getmetatable setmetatable require tick time wait spawn delay settings getgenv getrenv " +
    "hookfunction hookmetamethod newcclosure getgc getreg getinstances").split(" ")
);

// Luau is Lua with a few extra words and a `continue` statement. The stock
// Lua mode would leave `continue`/`type`/`export` as plain identifiers, which
// reads as a typo in the editor; this tokenizer knows them.
export const luau = StreamLanguage.define({
  name: "luau",
  startState: () => ({ long: null }),
  token(stream, state) {
    if (state.long) {
      if (stream.match(state.long)) state.long = null;
      else stream.skipToEnd();
      return "string";
    }

    if (stream.eatSpace()) return null;

    if (stream.match("--")) {
      const open = stream.match(/^\[(=*)\[/);
      if (open) state.long = "]" + "=".repeat(open[1].length) + "]";
      else stream.skipToEnd();
      return "comment";
    }

    const longOpen = stream.match(/^\[(=*)\[/);
    if (longOpen) {
      state.long = "]" + "=".repeat(longOpen[1].length) + "]";
      return "string";
    }

    const quote = stream.peek();
    if (quote === '"' || quote === "'") {
      stream.next();
      while (!stream.eol()) {
        const ch = stream.next();
        if (ch === "\\") stream.next();
        else if (ch === quote) break;
      }
      return "string";
    }

    const num = stream.match(
      /^(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/
    );
    if (num) return "number";

    const word = stream.match(/^[A-Za-z_][A-Za-z0-9_]*/);
    if (word) {
      const w = word[0];
      if (KEYWORDS.has(w)) return "keyword";
      if (BUILTINS.has(w)) return "builtin";
      if (stream.peek() === "(") return "def";
      return "variable";
    }

    if (stream.match(/^(?:\.\.\.|\.\.|==|~=|<=|>=|::|[-+*/%^#<>=~&|])/)) return "operator";
    if (stream.match(/^[{}()[\];,.:]/)) return "operator";

    stream.next();
    return null;
  },
});
