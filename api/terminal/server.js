// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke
'use strict';

const http = require('http');
const path = require('path');
const readline = require('readline');
const { WebSocketServer } = require('ws');
const auth = require('../auth');

/* -------------------------------------------------------------------------
 * Configuration
 * ---------------------------------------------------------------------- */

const PORT = parseInt(process.env.ELA_TERMINAL_PORT || '8080', 10);
const HEARTBEAT_INTERVAL_MS = 30000;
const VALIDATE_KEY = process.argv.includes('--validate-key');

/* -------------------------------------------------------------------------
 * Session registry
 * ---------------------------------------------------------------------- */

// mac -> { ws, mac, alias, lastHeartbeat, heartbeatTimer, outputBuffer }
const sessions = new Map();

function addSession(mac, ws) {
  const entry = {
    ws,
    mac,
    alias: null,
    lastHeartbeat: null,
    heartbeatTimer: null,
    outputBuffer: [],
  };

  entry.heartbeatTimer = setInterval(() => {
    if (ws.readyState === ws.OPEN) {
      ws.send(JSON.stringify({ _type: 'heartbeat' }));
    }
  }, HEARTBEAT_INTERVAL_MS);

  sessions.set(mac, entry);
  return entry;
}

function removeSession(mac) {
  const entry = sessions.get(mac);
  if (entry) {
    clearInterval(entry.heartbeatTimer);
    sessions.delete(mac);
  }
}

/* -------------------------------------------------------------------------
 * WebSocket server
 * ---------------------------------------------------------------------- */

const httpServer = http.createServer((req, res) => {
  res.writeHead(404);
  res.end();
});

const wss = new WebSocketServer({
  server: httpServer,
  path: '/terminal',
  verifyClient(info, done) {
    if (auth.checkBearer(info.req.headers['authorization'])) {
      done(true);
    } else {
      done(false, 401, 'Unauthorized');
    }
  },
});

wss.on('connection', (ws, req) => {
  // Extract MAC from URL: /terminal/<mac>
  const parts = (req.url || '').split('/').filter(Boolean);
  const mac = parts[1] || 'unknown';

  // If a session for this MAC already exists, close the old one
  const existing = sessions.get(mac);
  if (existing) {
    existing.ws.close();
    removeSession(mac);
  }

  const entry = addSession(mac, ws);

  // Notify TUI of new connection
  if (tui.state === TUI_STATE.SESSION_LIST) {
    tui.render();
  }

  ws.on('message', (data) => {
    const text = data.toString();

    // Try to parse heartbeat_ack
    try {
      const msg = JSON.parse(text);
      if (msg._type === 'heartbeat_ack') {
        entry.lastHeartbeat = msg.date || new Date().toISOString();
        return;
      }
    } catch (_) {
      // not JSON — treat as raw output
    }

    // Deliver to TUI if this is the active session
    if (tui.state === TUI_STATE.ACTIVE_SESSION &&
        tui.activeMac === mac) {
      process.stdout.write(text);
      tui.prompt(entry);
    } else {
      // Buffer output for when the session is attached
      entry.outputBuffer.push(text);
      if (entry.outputBuffer.length > 500) {
        entry.outputBuffer.shift();
      }
    }
  });

  ws.on('close', () => {
    removeSession(mac);
    if (tui.state === TUI_STATE.ACTIVE_SESSION && tui.activeMac === mac) {
      process.stdout.write('\r\n[session disconnected]\r\n');
      tui.detach();
    } else if (tui.state === TUI_STATE.SESSION_LIST) {
      tui.render();
    }
  });

  ws.on('error', () => {
    removeSession(mac);
  });
});

/* -------------------------------------------------------------------------
 * TUI
 * ---------------------------------------------------------------------- */

const TUI_STATE = { SESSION_LIST: 'SESSION_LIST', ACTIVE_SESSION: 'ACTIVE_SESSION' };

const ANSI = {
  clear:       '\x1b[2J\x1b[H',
  reset:       '\x1b[0m',
  reverse:     '\x1b[7m',
  bold:        '\x1b[1m',
  dim:         '\x1b[2m',
  eraseLine:   '\x1b[2K\r',
};

const tui = {
  state:      TUI_STATE.SESSION_LIST,
  cursor:     0,       // index in session list
  activeMac:  null,
  lineBuffer: '',      // current line being typed in active session

  render() {
    if (this.state !== TUI_STATE.SESSION_LIST) return;

    const macs = [...sessions.keys()];
    let out = ANSI.clear;
    out += `${ANSI.bold}ela-terminal${ANSI.reset}  —  ${macs.length} session(s)\r\n`;
    out += '─'.repeat(60) + '\r\n';

    if (macs.length === 0) {
      out += `${ANSI.dim}  (no connected devices)${ANSI.reset}\r\n`;
    } else {
      for (let i = 0; i < macs.length; i++) {
        const mac = macs[i];
        const entry = sessions.get(mac);
        const hb = entry.lastHeartbeat
          ? `  last heartbeat: ${entry.lastHeartbeat}`
          : '';
        const label = entry.alias ? `${entry.alias} (${mac})` : mac;
        const line = `  ${label}${hb}`;
        if (i === this.cursor) {
          out += `${ANSI.reverse}${line}${ANSI.reset}\r\n`;
        } else {
          out += `${line}\r\n`;
        }
      }
    }

    out += '\r\n' + `${ANSI.dim}↑/↓ navigate   Enter attach   q quit${ANSI.reset}\r\n`;
    process.stdout.write(out);
  },

  prompt(entry) {
    const mac = entry.mac;
    const p = entry.alias ? `${entry.alias} (${mac})> ` : `(${mac})> `;
    process.stdout.write(p);
  },

  attach(mac) {
    const entry = sessions.get(mac);
    if (!entry) return;

    this.state     = TUI_STATE.ACTIVE_SESSION;
    this.activeMac = mac;
    this.lineBuffer = '';

    const label = entry.alias ? `${entry.alias} (${mac})` : mac;
    process.stdout.write(ANSI.clear);
    process.stdout.write(
      `${ANSI.bold}Attached to ${label}${ANSI.reset}  (type 'detach' + Enter to return)\r\n` +
      '─'.repeat(60) + '\r\n'
    );

    // Flush buffered output
    if (entry.outputBuffer.length > 0) {
      process.stdout.write(entry.outputBuffer.join(''));
      entry.outputBuffer = [];
    }

    this.prompt(entry);
  },

  detach() {
    this.state     = TUI_STATE.SESSION_LIST;
    this.activeMac = null;
    this.lineBuffer = '';
    // Clamp cursor
    const count = sessions.size;
    if (this.cursor >= count) this.cursor = Math.max(0, count - 1);
    this.render();
  },

  handleKey(key, name, ctrl) {
    if (this.state === TUI_STATE.SESSION_LIST) {
      this._handleListKey(name, ctrl);
    } else {
      this._handleSessionKey(key, name, ctrl);
    }
  },

  _handleListKey(name, ctrl) {
    const macs = [...sessions.keys()];

    if (name === 'up' || name === 'k') {
      if (this.cursor > 0) this.cursor--;
      this.render();
    } else if (name === 'down' || name === 'j') {
      if (this.cursor < macs.length - 1) this.cursor++;
      this.render();
    } else if (name === 'return' && macs.length > 0) {
      const mac = macs[this.cursor];
      if (mac) this.attach(mac);
    } else if (name === 'q' || (ctrl && name === 'c')) {
      cleanup();
      process.exit(0);
    }
  },

  _handleSessionKey(key, name, ctrl) {
    if (ctrl && name === 'c') {
      cleanup();
      process.exit(0);
    }

    const entry = sessions.get(this.activeMac);

    if (name === 'return') {
      const line = this.lineBuffer;
      this.lineBuffer = '';
      process.stdout.write('\r\n');

      if (line === 'detach') {
        this.detach();
        return;
      }

      if (line.startsWith('name ') || line === 'name') {
        const alias = line.slice(5).trim();
        if (!alias) {
          process.stdout.write('[usage: name <alias>]\r\n');
        } else if (entry) {
          entry.alias = alias;
          process.stdout.write(`[device named: ${alias}]\r\n`);
        }
        if (entry) this.prompt(entry);
        return;
      }

      if (entry && entry.ws.readyState === entry.ws.OPEN) {
        entry.ws.send(line + '\n');
      }
      if (entry) this.prompt(entry);
      return;
    }

    if (name === 'backspace') {
      if (this.lineBuffer.length > 0) {
        this.lineBuffer = this.lineBuffer.slice(0, -1);
        // Erase last character on terminal
        process.stdout.write('\b \b');
      }
      return;
    }

    // Printable character
    if (key && key.length === 1 && key.charCodeAt(0) >= 0x20) {
      this.lineBuffer += key;
      process.stdout.write(key);
    }
  },
};

/* -------------------------------------------------------------------------
 * stdin raw-mode keypress handling
 * ---------------------------------------------------------------------- */

function setupInput() {
  if (!process.stdin.isTTY) {
    process.stderr.write('Warning: stdin is not a TTY; interactive TUI unavailable.\n');
    return;
  }

  readline.emitKeypressEvents(process.stdin);
  process.stdin.setRawMode(true);

  process.stdin.on('keypress', (key, info) => {
    const name = info && info.name;
    const ctrl = info && info.ctrl;
    tui.handleKey(key, name, ctrl);
  });
}

/* -------------------------------------------------------------------------
 * Startup / shutdown
 * ---------------------------------------------------------------------- */

function cleanup() {
  for (const [mac] of sessions) {
    removeSession(mac);
  }
  if (process.stdin.isTTY) {
    process.stdin.setRawMode(false);
  }
  process.stdout.write(ANSI.reset + '\r\n');
}

process.on('SIGINT', () => { cleanup(); process.exit(0); });
process.on('SIGTERM', () => { cleanup(); process.exit(0); });

if (!auth.init(path.join(__dirname, '..', 'ela.key'), VALIDATE_KEY)) {
  process.stderr.write(
    'error: --validate-key is set but ela.key is missing or contains no valid tokens\n'
  );
  process.exit(1);
}

httpServer.listen(PORT, () => {
  setupInput();
  tui.render();
});
