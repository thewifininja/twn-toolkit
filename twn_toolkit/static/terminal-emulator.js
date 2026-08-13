(function () {
  "use strict";

  class TwnTerminalEmulator {
    constructor(element, options = {}) {
      this.element = element;
      this.onData = typeof options.onData === "function" ? options.onData : () => {};
      this.maxScrollback = Math.max(1000, Number(options.scrollback || 12000));
      this.columns = 120;
      this.rows = 32;
      this.pending = "";
      this.savedScreen = null;
      this.reset(this.columns, this.rows);
    }

    reset(columns = this.columns, rows = this.rows) {
      this.columns = this._dimension(columns, 40, 300);
      this.rows = this._dimension(rows, 10, 120);
      this.history = [];
      this.screen = Array.from({length: this.rows}, () => this._blankLine());
      this.cursorX = 0;
      this.cursorY = 0;
      this.savedCursor = {x: 0, y: 0};
      this.scrollTop = 0;
      this.scrollBottom = this.rows - 1;
      this.wrapPending = false;
      this.applicationCursor = false;
      this.backspaceSendsBackspace = false;
      this.bracketedPaste = false;
      this.cursorVisible = true;
      this.attributes = this._defaultAttributes();
      this.alternate = false;
      this.savedScreen = null;
      this.pending = "";
      this.hasOutput = false;
      this.render();
    }

    resize(columns, rows) {
      const nextColumns = this._dimension(columns, 40, 300);
      const nextRows = this._dimension(rows, 10, 120);
      if (nextColumns === this.columns && nextRows === this.rows) return;

      this.columns = nextColumns;
      this.screen = this.screen.map((line) => this._resizeLine(line));
      this.history = this.history.map((line) => this._resizeLine(line));
      if (nextRows > this.rows) {
        while (this.screen.length < nextRows) this.screen.push(this._blankLine());
      } else if (nextRows < this.rows) {
        const removed = this.screen.splice(0, this.rows - nextRows);
        if (!this.alternate) this.history.push(...removed);
        this.cursorY = Math.max(0, this.cursorY - removed.length);
      }
      this.rows = nextRows;
      this.screen.length = nextRows;
      while (this.screen.length < nextRows) this.screen.push(this._blankLine());
      this.cursorX = Math.min(this.cursorX, this.columns - 1);
      this.cursorY = Math.min(this.cursorY, this.rows - 1);
      this.scrollTop = 0;
      this.scrollBottom = this.rows - 1;
      this._trimHistory();
      this.render();
    }

    write(value) {
      let data = this.pending + String(value || "");
      this.pending = "";
      if (!data) return;
      this.hasOutput = true;

      let index = 0;
      while (index < data.length) {
        const character = data[index];
        if (character === "\u001b") {
          const consumed = this._escape(data, index);
          if (!consumed) {
            this.pending = data.slice(index);
            break;
          }
          index += consumed;
          continue;
        }
        if (character === "\r") {
          this.cursorX = 0;
          this.wrapPending = false;
        } else if (character === "\n" || character === "\v" || character === "\f") {
          this._lineFeed();
        } else if (character === "\b") {
          this.wrapPending = false;
          this.cursorX = Math.max(0, this.cursorX - 1);
        } else if (character === "\t") {
          this.cursorX = Math.min(this.columns - 1, (Math.floor(this.cursorX / 8) + 1) * 8);
        } else if (character >= " " && character !== "\u007f") {
          this._print(character);
        }
        index += 1;
      }
      this._trimHistory();
      this.render();
    }

    keySequence(key) {
      const arrows = this.applicationCursor
        ? {ArrowUp: "\u001bOA", ArrowDown: "\u001bOB", ArrowRight: "\u001bOC", ArrowLeft: "\u001bOD", Home: "\u001bOH", End: "\u001bOF"}
        : {ArrowUp: "\u001b[A", ArrowDown: "\u001b[B", ArrowRight: "\u001b[C", ArrowLeft: "\u001b[D", Home: "\u001b[H", End: "\u001b[F"};
      return {
        Enter: "\r",
        Backspace: this.backspaceSendsBackspace ? "\b" : "\u007f",
        Tab: "\t",
        Escape: "\u001b",
        Delete: "\u001b[3~",
        Insert: "\u001b[2~",
        PageUp: "\u001b[5~",
        PageDown: "\u001b[6~",
        F1: "\u001bOP",
        F2: "\u001bOQ",
        F3: "\u001bOR",
        F4: "\u001bOS",
        F5: "\u001b[15~",
        F6: "\u001b[17~",
        F7: "\u001b[18~",
        F8: "\u001b[19~",
        F9: "\u001b[20~",
        F10: "\u001b[21~",
        F11: "\u001b[23~",
        F12: "\u001b[24~",
        ...arrows,
      }[key] || "";
    }

    formatPaste(value) {
      const text = String(value || "").replace(/\r\n|\n|\r/g, "\r");
      return this.bracketedPaste ? `\u001b[200~${text}\u001b[201~` : text;
    }

    render() {
      const nearBottom = this.element.scrollHeight - this.element.scrollTop - this.element.clientHeight < 80;
      if (!this.hasOutput) {
        this.element.replaceChildren();
        return;
      }
      const lastScreenLine = Math.max(
        this.cursorY,
        this.screen.reduce((last, line, index) => this._lineText(line) ? index : last, 0)
      );
      const lines = [...this.history, ...this.screen.slice(0, lastScreenLine + 1)];
      const cursorLine = this.history.length + this.cursorY;
      const fragment = document.createDocumentFragment();
      lines.forEach((line, lineIndex) => {
        const contentEnd = this._contentEnd(line);
        const visibleEnd = lineIndex === cursorLine && this.cursorVisible
          ? Math.max(contentEnd, this.cursorX + 1)
          : contentEnd;
        this._renderLine(fragment, line, visibleEnd, lineIndex === cursorLine);
        if (lineIndex < lines.length - 1) fragment.append(document.createTextNode("\n"));
      });
      this.element.replaceChildren(fragment);
      if (nearBottom) this.element.scrollTop = this.element.scrollHeight;
    }

    _escape(data, start) {
      if (start + 1 >= data.length) return 0;
      const introducer = data[start + 1];
      if (introducer === "[") {
        let end = start + 2;
        while (end < data.length && !(data.charCodeAt(end) >= 0x40 && data.charCodeAt(end) <= 0x7e)) end += 1;
        if (end >= data.length) return 0;
        this._csi(data.slice(start + 2, end), data[end]);
        return end - start + 1;
      }
      if (introducer === "]") {
        const bell = data.indexOf("\u0007", start + 2);
        const terminator = data.indexOf("\u001b\\", start + 2);
        const end = bell >= 0 && (terminator < 0 || bell < terminator) ? bell : terminator;
        if (end < 0) return 0;
        return end - start + (end === bell ? 1 : 2);
      }
      if (["P", "_", "^"].includes(introducer)) {
        const end = data.indexOf("\u001b\\", start + 2);
        return end < 0 ? 0 : end - start + 2;
      }
      this._singleEscape(introducer);
      return 2;
    }

    _singleEscape(code) {
      if (code === "7") this.savedCursor = {x: this.cursorX, y: this.cursorY};
      else if (code === "8") this._restoreCursor();
      else if (code === "D") this._lineFeed();
      else if (code === "E") {
        this.cursorX = 0;
        this._lineFeed();
      } else if (code === "M") this._reverseIndex();
      else if (code === "c") this.reset(this.columns, this.rows);
      else if (code === "Z") this.onData("\u001b[?1;2c");
    }

    _csi(parameters, final) {
      const privateMode = parameters.startsWith("?");
      const clean = parameters.replace(/^[?>!]/, "").replace(/[ -/].*$/, "");
      const values = clean.split(";").map((value) => value === "" ? 0 : Number(value) || 0);
      const amount = (fallback = 1, index = 0) => Math.max(1, values[index] || fallback);

      if (final === "A") this.cursorY = Math.max(this.scrollTop, this.cursorY - amount());
      else if (final === "B" || final === "e") this.cursorY = Math.min(this.scrollBottom, this.cursorY + amount());
      else if (final === "C" || final === "a") this.cursorX = Math.min(this.columns - 1, this.cursorX + amount());
      else if (final === "D") this.cursorX = Math.max(0, this.cursorX - amount());
      else if (final === "E") {
        this.cursorY = Math.min(this.scrollBottom, this.cursorY + amount());
        this.cursorX = 0;
      } else if (final === "F") {
        this.cursorY = Math.max(this.scrollTop, this.cursorY - amount());
        this.cursorX = 0;
      } else if (final === "G" || final === "`") this.cursorX = Math.min(this.columns - 1, amount() - 1);
      else if (final === "d") this.cursorY = Math.min(this.rows - 1, amount() - 1);
      else if (final === "H" || final === "f") {
        this.cursorY = Math.min(this.rows - 1, amount(1, 0) - 1);
        this.cursorX = Math.min(this.columns - 1, amount(1, 1) - 1);
      } else if (final === "J") this._eraseDisplay(values[0] || 0);
      else if (final === "K") this._eraseLine(values[0] || 0);
      else if (final === "@") this._insertCharacters(amount());
      else if (final === "P") this._deleteCharacters(amount());
      else if (final === "X") this._eraseCharacters(amount());
      else if (final === "L") this._insertLines(amount());
      else if (final === "M") this._deleteLines(amount());
      else if (final === "S") this._scrollUp(amount());
      else if (final === "T") this._scrollDown(amount());
      else if (final === "s") this.savedCursor = {x: this.cursorX, y: this.cursorY};
      else if (final === "u") this._restoreCursor();
      else if (final === "r") this._setScrollRegion(values);
      else if (final === "m") this._setGraphicRendition(values);
      else if (final === "n" && values[0] === 6) this.onData(`\u001b[${this.cursorY + 1};${this.cursorX + 1}R`);
      else if (final === "c") this.onData("\u001b[?1;2c");
      else if ((final === "h" || final === "l") && privateMode) this._setPrivateModes(values, final === "h");
      this.wrapPending = false;
    }

    _setPrivateModes(values, enabled) {
      values.forEach((mode) => {
        if (mode === 1) this.applicationCursor = enabled;
        else if (mode === 25) this.cursorVisible = enabled;
        else if (mode === 67) this.backspaceSendsBackspace = enabled;
        else if (mode === 2004) this.bracketedPaste = enabled;
        else if ([47, 1047, 1049].includes(mode)) {
          if (enabled) this._enterAlternate();
          else this._exitAlternate();
        }
      });
    }

    _setGraphicRendition(values) {
      const codes = values.length ? values : [0];
      codes.forEach((code) => {
        if (code === 0) this.attributes = this._defaultAttributes();
        else if (code === 1) this.attributes.bold = true;
        else if (code === 2) this.attributes.dim = true;
        else if (code === 3) this.attributes.italic = true;
        else if (code === 4) this.attributes.underline = true;
        else if (code === 7) this.attributes.inverse = true;
        else if (code === 22) {
          this.attributes.bold = false;
          this.attributes.dim = false;
        } else if (code === 23) this.attributes.italic = false;
        else if (code === 24) this.attributes.underline = false;
        else if (code === 27) this.attributes.inverse = false;
        else if (code >= 30 && code <= 37) this.attributes.foreground = code - 30;
        else if (code === 39) this.attributes.foreground = null;
        else if (code >= 40 && code <= 47) this.attributes.background = code - 40;
        else if (code === 49) this.attributes.background = null;
        else if (code >= 90 && code <= 97) this.attributes.foreground = code - 82;
        else if (code >= 100 && code <= 107) this.attributes.background = code - 92;
      });
    }

    _enterAlternate() {
      if (this.alternate) return;
      this.savedScreen = {
        history: this.history,
        screen: this.screen.map((line) => line.slice()),
        cursorX: this.cursorX,
        cursorY: this.cursorY,
        savedCursor: {...this.savedCursor},
        attributes: {...this.attributes},
        scrollTop: this.scrollTop,
        scrollBottom: this.scrollBottom,
        wrapPending: this.wrapPending,
      };
      this.alternate = true;
      this.history = [];
      this.screen = Array.from({length: this.rows}, () => this._blankLine());
      this.cursorX = 0;
      this.cursorY = 0;
      this.scrollTop = 0;
      this.scrollBottom = this.rows - 1;
    }

    _exitAlternate() {
      if (!this.alternate || !this.savedScreen) return;
      Object.assign(this, this.savedScreen);
      this.savedScreen = null;
      this.alternate = false;
    }

    _print(character) {
      if (this.wrapPending) {
        this.cursorX = 0;
        this._lineFeed();
        this.wrapPending = false;
      }
      this.screen[this.cursorY][this.cursorX] = {
        character,
        style: this._attributeClass(),
      };
      if (this.cursorX >= this.columns - 1) this.wrapPending = true;
      else this.cursorX += 1;
    }

    _lineFeed() {
      this.wrapPending = false;
      if (this.cursorY === this.scrollBottom) this._scrollUp(1);
      else this.cursorY = Math.min(this.rows - 1, this.cursorY + 1);
    }

    _reverseIndex() {
      if (this.cursorY === this.scrollTop) this._scrollDown(1);
      else this.cursorY = Math.max(0, this.cursorY - 1);
    }

    _scrollUp(amount) {
      for (let index = 0; index < amount; index += 1) {
        const removed = this.screen.splice(this.scrollTop, 1)[0];
        this.screen.splice(this.scrollBottom, 0, this._blankLine());
        if (this.scrollTop === 0 && !this.alternate) this.history.push(removed);
      }
    }

    _scrollDown(amount) {
      for (let index = 0; index < amount; index += 1) {
        this.screen.splice(this.scrollBottom, 1);
        this.screen.splice(this.scrollTop, 0, this._blankLine());
      }
    }

    _eraseDisplay(mode) {
      if (mode === 2 || mode === 3) {
        this.screen = Array.from({length: this.rows}, () => this._blankLine());
        if (mode === 3) this.history = [];
      } else if (mode === 1) {
        for (let row = 0; row < this.cursorY; row += 1) this.screen[row] = this._blankLine();
        this._eraseRange(this.screen[this.cursorY], 0, this.cursorX + 1);
      } else {
        this._eraseRange(this.screen[this.cursorY], this.cursorX, this.columns);
        for (let row = this.cursorY + 1; row < this.rows; row += 1) this.screen[row] = this._blankLine();
      }
    }

    _eraseLine(mode) {
      if (mode === 2) this.screen[this.cursorY] = this._blankLine();
      else if (mode === 1) this._eraseRange(this.screen[this.cursorY], 0, this.cursorX + 1);
      else this._eraseRange(this.screen[this.cursorY], this.cursorX, this.columns);
    }

    _insertCharacters(amount) {
      const line = this.screen[this.cursorY];
      line.splice(
        this.cursorX,
        0,
        ...Array.from({length: Math.min(amount, this.columns)}, () => this._blankCell())
      );
      line.length = this.columns;
    }

    _deleteCharacters(amount) {
      const line = this.screen[this.cursorY];
      line.splice(this.cursorX, amount);
      while (line.length < this.columns) line.push(this._blankCell());
    }

    _eraseCharacters(amount) {
      this._eraseRange(
        this.screen[this.cursorY],
        this.cursorX,
        Math.min(this.columns, this.cursorX + amount)
      );
    }

    _insertLines(amount) {
      if (this.cursorY < this.scrollTop || this.cursorY > this.scrollBottom) return;
      for (let index = 0; index < amount; index += 1) {
        this.screen.splice(this.cursorY, 0, this._blankLine());
        this.screen.splice(this.scrollBottom + 1, 1);
      }
    }

    _deleteLines(amount) {
      if (this.cursorY < this.scrollTop || this.cursorY > this.scrollBottom) return;
      for (let index = 0; index < amount; index += 1) {
        this.screen.splice(this.cursorY, 1);
        this.screen.splice(this.scrollBottom, 0, this._blankLine());
      }
    }

    _setScrollRegion(values) {
      const top = Math.max(0, (values[0] || 1) - 1);
      const bottom = Math.min(this.rows - 1, (values[1] || this.rows) - 1);
      if (top >= bottom) return;
      this.scrollTop = top;
      this.scrollBottom = bottom;
      this.cursorX = 0;
      this.cursorY = 0;
    }

    _restoreCursor() {
      this.cursorX = Math.min(this.columns - 1, Math.max(0, this.savedCursor.x));
      this.cursorY = Math.min(this.rows - 1, Math.max(0, this.savedCursor.y));
    }

    _renderLine(fragment, line, visibleEnd, cursorLine) {
      let position = 0;
      while (position < visibleEnd) {
        if (cursorLine && this.cursorVisible && position === this.cursorX) {
          const cursor = document.createElement("span");
          cursor.className = ["remote-terminal-cursor", line[position]?.style]
            .filter(Boolean)
            .join(" ");
          cursor.textContent = line[position]?.character || " ";
          fragment.append(cursor);
          position += 1;
          continue;
        }
        const style = line[position]?.style || "";
        let end = position + 1;
        while (
          end < visibleEnd
          && !(cursorLine && this.cursorVisible && end === this.cursorX)
          && (line[end]?.style || "") === style
        ) end += 1;
        const text = line
          .slice(position, end)
          .map((cell) => cell?.character || " ")
          .join("");
        if (style) {
          const span = document.createElement("span");
          span.className = style;
          span.textContent = text;
          fragment.append(span);
        } else {
          fragment.append(document.createTextNode(text));
        }
        position = end;
      }
    }

    _attributeClass() {
      const classes = [];
      if (this.attributes.foreground !== null) classes.push(`terminal-fg-${this.attributes.foreground}`);
      if (this.attributes.background !== null) classes.push(`terminal-bg-${this.attributes.background}`);
      if (this.attributes.bold) classes.push("terminal-bold");
      if (this.attributes.dim) classes.push("terminal-dim");
      if (this.attributes.italic) classes.push("terminal-italic");
      if (this.attributes.underline) classes.push("terminal-underline");
      if (this.attributes.inverse) classes.push("terminal-inverse");
      return classes.join(" ");
    }

    _defaultAttributes() {
      return {
        foreground: null,
        background: null,
        bold: false,
        dim: false,
        italic: false,
        underline: false,
        inverse: false,
      };
    }

    _eraseRange(line, start, end) {
      for (let index = start; index < end; index += 1) line[index] = this._blankCell();
    }

    _trimHistory() {
      if (this.history.length > this.maxScrollback) {
        this.history.splice(0, this.history.length - this.maxScrollback);
      }
    }

    _blankLine() {
      return Array.from({length: this.columns}, () => this._blankCell());
    }

    _blankCell() {
      return {character: " ", style: ""};
    }

    _resizeLine(line) {
      const resized = line.slice(0, this.columns);
      while (resized.length < this.columns) resized.push(this._blankCell());
      return resized;
    }

    _lineText(line) {
      return line.map((cell) => cell.character).join("").replace(/\s+$/, "");
    }

    _contentEnd(line) {
      for (let index = line.length - 1; index >= 0; index -= 1) {
        if (line[index].character !== " ") return index + 1;
      }
      return 0;
    }

    _dimension(value, minimum, maximum) {
      return Math.max(minimum, Math.min(maximum, Math.round(Number(value) || minimum)));
    }
  }

  window.TwnTerminalEmulator = TwnTerminalEmulator;
})();
