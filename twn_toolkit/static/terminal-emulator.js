(function () {
  "use strict";

  class TwnTerminalEmulator {
    constructor(element, options = {}) {
      this.element = element;
      this.onData = typeof options.onData === "function" ? options.onData : () => {};
      this.maxScrollback = Math.max(1000, Number(options.scrollback || 100000));
      this.renderOverscan = Math.max(40, Number(options.renderOverscan || 120));
      this.columns = 120;
      this.rows = 32;
      this.pending = "";
      this.savedScreen = null;
      this.trimmedHistory = 0;
      this._renderFrame = null;
      this._rendering = false;
      this.element.addEventListener("scroll", () => this._scheduleViewportRender());
      this.reset(this.columns, this.rows);
    }

    reset(columns = this.columns, rows = this.rows) {
      this.columns = this._dimension(columns, 40, 300);
      this.rows = this._dimension(rows, 10, 120);
      this._syncElementDimensions();
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
      this.trimmedHistory = 0;
      this.render();
    }

    resize(columns, rows) {
      const nextColumns = this._dimension(columns, 40, 300);
      const nextRows = this._dimension(rows, 10, 120);
      if (nextColumns === this.columns && nextRows === this.rows) return;

      this.columns = nextColumns;
      this.screen = this.screen.map((line) => this._resizeLine(line));
      if (nextRows > this.rows) {
        while (this.screen.length < nextRows) this.screen.push(this._blankLine());
      } else if (nextRows < this.rows) {
        const removed = this.screen.splice(0, this.rows - nextRows);
        if (!this.alternate) {
          this.history.push(...removed.map((line) => this._serializeLine(line)));
        }
        this.cursorY = Math.max(0, this.cursorY - removed.length);
      }
      this.rows = nextRows;
      this._syncElementDimensions();
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

    serialize(options = {}) {
      const requestedLimit = Number(options.historyLimit ?? this.maxScrollback);
      const historyLimit = Number.isFinite(requestedLimit)
        ? Math.max(0, Math.min(this.maxScrollback, requestedLimit))
        : this.maxScrollback;
      const checkpointHistory = historyLimit ? this.history.slice(-historyLimit) : [];
      return {
        version: 1,
        columns: this.columns,
        rows: this.rows,
        history: checkpointHistory.map((line) => this._copySerializedLine(line)),
        screen: this.screen.map((line) => this._serializeLine(line)),
        cursorX: this.cursorX,
        cursorY: this.cursorY,
        savedCursor: {...this.savedCursor},
        scrollTop: this.scrollTop,
        scrollBottom: this.scrollBottom,
        wrapPending: this.wrapPending,
        applicationCursor: this.applicationCursor,
        backspaceSendsBackspace: this.backspaceSendsBackspace,
        bracketedPaste: this.bracketedPaste,
        cursorVisible: this.cursorVisible,
        attributes: {...this.attributes},
        alternate: this.alternate,
        savedScreen: this.savedScreen ? this._serializeSavedScreen(this.savedScreen) : null,
        pending: this.pending,
        hasOutput: this.hasOutput,
        trimmedHistory: this.trimmedHistory + Math.max(0, this.history.length - historyLimit),
      };
    }

    restore(snapshot) {
      if (
        !snapshot
        || snapshot.version !== 1
        || !Array.isArray(snapshot.history)
        || !Array.isArray(snapshot.screen)
        || !snapshot.screen.length
      ) return false;
      try {
        const columns = this._dimension(snapshot.columns, 40, 300);
        const rows = this._dimension(snapshot.rows, 10, 120);
        this.columns = columns;
        this.rows = rows;
        this._syncElementDimensions();
        this.history = this._restoreSerializedLines(snapshot.history, this.maxScrollback);
        this.screen = this._restoreLines(snapshot.screen, rows);
        this.screen.length = Math.min(this.screen.length, rows);
        while (this.screen.length < rows) this.screen.push(this._blankLine());
        this.cursorX = this._position(snapshot.cursorX, columns - 1);
        this.cursorY = this._position(snapshot.cursorY, rows - 1);
        this.savedCursor = {
          x: this._position(snapshot.savedCursor?.x, columns - 1),
          y: this._position(snapshot.savedCursor?.y, rows - 1),
        };
        this.scrollTop = this._position(snapshot.scrollTop, rows - 1);
        this.scrollBottom = Math.max(
          this.scrollTop,
          this._position(snapshot.scrollBottom, rows - 1)
        );
        this.wrapPending = Boolean(snapshot.wrapPending);
        this.applicationCursor = Boolean(snapshot.applicationCursor);
        this.backspaceSendsBackspace = Boolean(snapshot.backspaceSendsBackspace);
        this.bracketedPaste = Boolean(snapshot.bracketedPaste);
        this.cursorVisible = snapshot.cursorVisible !== false;
        this.attributes = this._restoreAttributes(snapshot.attributes);
        this.alternate = Boolean(snapshot.alternate);
        this.savedScreen = snapshot.savedScreen
          ? this._restoreSavedScreen(snapshot.savedScreen, columns, rows)
          : null;
        this.pending = String(snapshot.pending || "").slice(0, 4096);
        this.hasOutput = Boolean(snapshot.hasOutput || this.history.length || this.screen.some(
          (line) => this._contentEnd(line) > 0
        ));
        this.trimmedHistory = Math.max(0, Math.round(Number(snapshot.trimmedHistory) || 0));
        this._trimHistory();
        this.render();
        return true;
      } catch (_error) {
        return false;
      }
    }

    render(options = {}) {
      const followOutput = options.followOutput ?? this.isNearBottom();
      if (!this.hasOutput) {
        this.element.replaceChildren();
        return;
      }
      const lastScreenLine = Math.max(
        this.cursorY,
        this.screen.reduce((last, line, index) => this._lineText(line) ? index : last, 0)
      );
      const totalLines = this.history.length + lastScreenLine + 1;
      const cursorLine = this.history.length + this.cursorY;
      const lineHeight = this._lineHeight();
      const viewportLines = Math.max(1, Math.ceil(this.element.clientHeight / lineHeight));
      const firstVisible = followOutput
        ? Math.max(0, totalLines - viewportLines)
        : Math.max(0, Math.floor(this.element.scrollTop / lineHeight));
      const start = Math.max(0, firstVisible - this.renderOverscan);
      const end = Math.min(
        totalLines,
        firstVisible + viewportLines + this.renderOverscan
      );
      const fragment = document.createDocumentFragment();
      if (start) fragment.append(this._spacer(start * lineHeight));
      for (let lineIndex = start; lineIndex < end; lineIndex += 1) {
        const line = lineIndex < this.history.length
          ? this._deserializeLine(this.history[lineIndex])
          : this.screen[lineIndex - this.history.length];
        const lineElement = document.createElement("div");
        lineElement.className = "remote-terminal-line";
        const contentEnd = this._contentEnd(line);
        const visibleEnd = lineIndex === cursorLine && this.cursorVisible
          ? Math.max(contentEnd, this.cursorX + 1)
          : contentEnd;
        this._renderLine(lineElement, line, visibleEnd, lineIndex === cursorLine);
        fragment.append(lineElement);
      }
      if (end < totalLines) fragment.append(this._spacer((totalLines - end) * lineHeight));
      this._rendering = true;
      this.element.replaceChildren(fragment);
      if (followOutput) this.element.scrollTop = this.element.scrollHeight;
      this._rendering = false;
    }

    isNearBottom() {
      return this.element.scrollHeight - this.element.scrollTop - this.element.clientHeight < 80;
    }

    scrollToBottom() {
      this.render({followOutput: true});
    }

    scrollToCursor() {
      const computed = window.getComputedStyle?.(this.element);
      const paddingLeft = Number.parseFloat(computed?.paddingLeft || "") || 0;
      const probe = document.createElement("span");
      probe.textContent = "0";
      probe.style.cssText = "position:absolute;visibility:hidden;white-space:pre";
      this.element.append(probe);
      const characterWidth = probe.getBoundingClientRect().width || 8;
      probe.remove();
      const cursorLeft = paddingLeft + this.cursorX * characterWidth;
      const visibleLeft = this.element.scrollLeft;
      const visibleRight = visibleLeft + this.element.clientWidth;
      if (cursorLeft < visibleLeft) {
        this.element.scrollLeft = Math.max(0, cursorLeft - characterWidth);
      } else if (cursorLeft + characterWidth > visibleRight) {
        this.element.scrollLeft = Math.max(
          0,
          cursorLeft + characterWidth - this.element.clientWidth + paddingLeft
        );
      }
    }

    hasTrimmedHistory() {
      return this.trimmedHistory > 0;
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
        if (this.scrollTop === 0 && !this.alternate) {
          this.history.push(this._serializeLine(removed));
        }
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

    _serializeSavedScreen(saved) {
      return {
        history: (saved.history || []).map((line) => this._copySerializedLine(line)),
        screen: (saved.screen || []).map((line) => this._serializeLine(line)),
        cursorX: saved.cursorX,
        cursorY: saved.cursorY,
        savedCursor: {...(saved.savedCursor || {x: 0, y: 0})},
        attributes: {...(saved.attributes || this._defaultAttributes())},
        scrollTop: saved.scrollTop,
        scrollBottom: saved.scrollBottom,
        wrapPending: saved.wrapPending,
      };
    }

    _restoreSavedScreen(saved, columns, rows) {
      const screen = this._restoreLines(saved.screen, rows);
      screen.length = Math.min(screen.length, rows);
      while (screen.length < rows) screen.push(this._blankLine());
      return {
        history: this._restoreSerializedLines(saved.history, this.maxScrollback),
        screen,
        cursorX: this._position(saved.cursorX, columns - 1),
        cursorY: this._position(saved.cursorY, rows - 1),
        savedCursor: {
          x: this._position(saved.savedCursor?.x, columns - 1),
          y: this._position(saved.savedCursor?.y, rows - 1),
        },
        attributes: this._restoreAttributes(saved.attributes),
        scrollTop: this._position(saved.scrollTop, rows - 1),
        scrollBottom: this._position(saved.scrollBottom, rows - 1),
        wrapPending: Boolean(saved.wrapPending),
      };
    }

    _serializeLine(line) {
      let end = 0;
      for (let index = line.length - 1; index >= 0; index -= 1) {
        if ((line[index]?.character || " ") !== " " || line[index]?.style) {
          end = index + 1;
          break;
        }
      }
      const runs = [];
      let position = 0;
      while (position < end) {
        const style = line[position]?.style || "";
        let next = position + 1;
        while (next < end && (line[next]?.style || "") === style) next += 1;
        runs.push([
          line.slice(position, next).map((cell) => cell?.character || " ").join(""),
          style,
        ]);
        position = next;
      }
      return runs;
    }

    _restoreLines(lines, limit) {
      if (!Array.isArray(lines)) return [];
      return lines.slice(-Math.max(0, limit)).map((runs) => {
        const line = this._blankLine();
        if (!Array.isArray(runs)) return line;
        let position = 0;
        for (const run of runs) {
          if (!Array.isArray(run) || position >= this.columns) continue;
          const text = String(run[0] || "");
          const style = this._restoreStyle(run[1]);
          for (let index = 0; index < text.length && position < this.columns; index += 1) {
            line[position] = {character: text[index], style};
            position += 1;
          }
        }
        return line;
      });
    }

    _restoreSerializedLines(lines, limit) {
      if (!Array.isArray(lines)) return [];
      return lines.slice(-Math.max(0, limit)).map((runs) => {
        if (!Array.isArray(runs)) return [];
        const restored = [];
        let remaining = this.columns;
        for (const run of runs) {
          if (!Array.isArray(run) || remaining <= 0) continue;
          const text = String(run[0] || "").slice(0, remaining);
          if (!text) continue;
          restored.push([text, this._restoreStyle(run[1])]);
          remaining -= text.length;
        }
        return restored;
      });
    }

    _copySerializedLine(line) {
      return Array.isArray(line)
        ? line.map((run) => [String(run?.[0] || ""), this._restoreStyle(run?.[1])])
        : [];
    }

    _deserializeLine(runs) {
      const line = this._blankLine();
      let position = 0;
      for (const run of runs || []) {
        const text = String(run?.[0] || "");
        const style = this._restoreStyle(run?.[1]);
        for (let index = 0; index < text.length && position < this.columns; index += 1) {
          line[position] = {character: text[index], style};
          position += 1;
        }
      }
      return line;
    }

    _restoreStyle(value) {
      const allowed = /^(?:terminal-(?:fg|bg)-(?:[0-9]|1[0-5])|terminal-(?:bold|dim|italic|underline|inverse))$/;
      return String(value || "")
        .split(/\s+/)
        .filter((item) => allowed.test(item))
        .join(" ");
    }

    _restoreAttributes(value) {
      const source = value && typeof value === "object" ? value : {};
      const color = (candidate) => {
        if (candidate === null || candidate === undefined || candidate === "") return null;
        const number = Number(candidate);
        return Number.isInteger(number) && number >= 0 && number <= 15 ? number : null;
      };
      return {
        foreground: color(source.foreground),
        background: color(source.background),
        bold: Boolean(source.bold),
        dim: Boolean(source.dim),
        italic: Boolean(source.italic),
        underline: Boolean(source.underline),
        inverse: Boolean(source.inverse),
      };
    }

    _position(value, maximum) {
      return Math.max(0, Math.min(maximum, Math.round(Number(value) || 0)));
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
        const removed = this.history.length - this.maxScrollback;
        this.history.splice(0, removed);
        this.trimmedHistory += removed;
      }
    }

    _syncElementDimensions() {
      this.element.style.setProperty("--terminal-columns", String(this.columns));
    }

    _lineHeight() {
      const computed = window.getComputedStyle?.(this.element);
      const lineHeight = Number.parseFloat(computed?.lineHeight || "");
      return Number.isFinite(lineHeight) && lineHeight > 0 ? lineHeight : 21;
    }

    _spacer(height) {
      const spacer = document.createElement("div");
      spacer.className = "remote-terminal-scroll-spacer";
      spacer.style.height = `${Math.max(0, height)}px`;
      spacer.setAttribute("aria-hidden", "true");
      return spacer;
    }

    _scheduleViewportRender() {
      if (this._rendering || this._renderFrame !== null || !this.hasOutput) return;
      this._renderFrame = window.requestAnimationFrame(() => {
        this._renderFrame = null;
        this.render({followOutput: false});
      });
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
