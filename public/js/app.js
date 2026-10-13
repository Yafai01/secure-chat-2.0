// Secure Chat client. All untrusted content (names, messages, room IDs) is
// rendered with textContent — never innerHTML.
import {
  MAX_NAME_LENGTH,
  MIN_PASSPHRASE_LENGTH,
  bytesToBase64,
  decryptMessage,
  deriveRoomKey,
  encryptMessage,
} from "./crypto.js";

const ROOM_ID_PATTERN = /^[A-Za-z0-9_-]{6,64}$/;
const ACK_TIMEOUT_MS = 8000;
const MAX_RENDERED_MESSAGES = 500;
const MAX_SEEN_IDS = 2000;

const ERROR_TEXT = {
  rate_limited: "You're sending too quickly. Wait a moment and try again.",
  invalid_room: "That room ID isn't valid.",
  payload_too_large: "That message is too long.",
  not_in_room: "You're not in a room. Rejoin and try again.",
  timeout: "The server didn't respond. Check your connection and try again.",
  offline: "You're offline. Reconnecting…",
};

const $ = (id) => document.getElementById(id);
const els = {
  status: $("status"),
  statusText: $("statusText"),
  joinView: $("joinView"),
  joinForm: $("joinForm"),
  name: $("name"),
  room: $("room"),
  passphrase: $("passphrase"),
  generateRoom: $("generateRoom"),
  togglePass: $("togglePass"),
  joinError: $("joinError"),
  joinBtn: $("joinBtn"),
  chatView: $("chatView"),
  roomTitle: $("roomTitle"),
  memberCount: $("memberCount"),
  fingerprint: $("fingerprint"),
  copyLink: $("copyLink"),
  leaveBtn: $("leaveBtn"),
  messages: $("messages"),
  emptyState: $("emptyState"),
  composer: $("composer"),
  messageInput: $("messageInput"),
  sendBtn: $("sendBtn"),
  composerError: $("composerError"),
};

/** @type {{ socket: any, room: string|null, key: CryptoKey|null, name: string, seen: Set<string> }} */
const state = { socket: null, room: null, key: null, name: "", seen: new Set() };

// ---------- helpers ----------

function storageGet(key) {
  try { return localStorage.getItem(key); } catch { return null; }
}
function storageSet(key, value) {
  try { localStorage.setItem(key, value); } catch { /* storage unavailable */ }
}

function setStatus(stateName, text) {
  els.status.dataset.state = stateName;
  els.statusText.textContent = text;
}

function showError(el, message) {
  el.textContent = message;
  el.hidden = !message;
}

function errorText(code) {
  return ERROR_TEXT[code] ?? "Something went wrong. Please try again.";
}

function randomRoomId() {
  return bytesToBase64(crypto.getRandomValues(new Uint8Array(12)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function roomFromLocation() {
  const params = new URLSearchParams(location.hash.slice(1));
  const room = params.get("room");
  return room && ROOM_ID_PATTERN.test(room) ? room : "";
}

function roomLink(room) {
  return `${location.origin}${location.pathname}#room=${encodeURIComponent(room)}`;
}

function formatTime(ts) {
  return new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function setBusy(button, busy, label) {
  button.disabled = busy;
  button.setAttribute("aria-busy", String(busy));
  if (label) button.querySelector(".label").textContent = label;
}

function emitWithAck(event, payload) {
  return new Promise((resolve) => {
    if (!state.socket?.connected) return resolve({ ok: false, error: "offline" });
    state.socket.timeout(ACK_TIMEOUT_MS).emit(event, payload, (err, response) => {
      if (err) resolve({ ok: false, error: "timeout" });
      else resolve(response ?? { ok: false, error: "unknown" });
    });
  });
}

// ---------- rendering ----------

function scrollToBottom() {
  els.messages.scrollTop = els.messages.scrollHeight;
}

function trimMessages() {
  while (els.messages.children.length > MAX_RENDERED_MESSAGES + 1) {
    const first = els.messages.firstElementChild === els.emptyState
      ? els.emptyState.nextElementSibling
      : els.messages.firstElementChild;
    first.remove();
  }
}

function renderMessage({ name, text, ts }, mine) {
  els.emptyState.hidden = true;

  const wrap = document.createElement("div");
  wrap.className = mine ? "msg mine" : "msg";

  const head = document.createElement("div");
  head.className = "msg-head";
  const who = document.createElement("span");
  who.className = "msg-name";
  who.textContent = mine ? "You" : name || "Anonymous";
  const time = document.createElement("time");
  time.dateTime = new Date(ts).toISOString();
  time.textContent = formatTime(ts);
  head.append(who, time);

  const body = document.createElement("div");
  body.className = "msg-body";
  body.textContent = text;

  wrap.append(head, body);
  els.messages.append(wrap);
  trimMessages();
  scrollToBottom();
}

function renderNotice(text, warn = false) {
  if (warn) els.emptyState.hidden = true;
  const last = els.messages.lastElementChild;
  if (last?.classList.contains("notice") && last.dataset.text === text) {
    const count = Number(last.dataset.count) + 1;
    last.dataset.count = String(count);
    last.textContent = `${text} (×${count})`;
    return;
  }
  const p = document.createElement("p");
  p.className = warn ? "notice warn" : "notice";
  p.dataset.text = text;
  p.dataset.count = "1";
  p.textContent = text;
  els.messages.append(p);
  trimMessages();
  scrollToBottom();
}

function clearMessages() {
  for (const child of [...els.messages.children]) {
    if (child !== els.emptyState) child.remove();
  }
  els.emptyState.hidden = false;
}

function setMemberCount(count) {
  els.memberCount.textContent = `${count} online`;
}

function updateSendButton() {
  els.sendBtn.disabled = !state.key || !state.socket?.connected || els.messageInput.value.trim() === "";
}

// ---------- socket ----------

function ensureSocket() {
  if (state.socket) return state.socket;

  // `io` is provided by /socket.io/socket.io.js, served by our own server.
  const socket = window.io({ autoConnect: false });
  state.socket = socket;

  socket.on("connect", async () => {
    setStatus("online", "Connected");
    updateSendButton();
    if (state.room) {
      // Rejoin after a reconnect; the server keeps no session state.
      const res = await emitWithAck("join", { room: state.room });
      if (res.ok) setMemberCount(res.count);
      else renderNotice(`Couldn't rejoin the room: ${errorText(res.error)}`, true);
    }
  });

  socket.on("disconnect", () => {
    setStatus("connecting", "Reconnecting…");
    updateSendButton();
  });

  socket.on("connect_error", () => {
    setStatus("connecting", "Connection problem, retrying…");
  });

  socket.on("presence", (data) => {
    if (Number.isInteger(data?.count)) setMemberCount(data.count);
  });

  socket.on("message", async (envelope) => {
    const { key, room } = state;
    if (!key || !room) return;
    try {
      const message = await decryptMessage(key, room, envelope);
      if (state.key !== key) return; // left the room while decrypting
      if (state.seen.has(message.id)) return; // drop replays
      rememberId(message.id);
      renderMessage(message, false);
    } catch {
      if (state.key === key) {
        renderNotice("A message couldn't be decrypted. The sender may be using a different passphrase.", true);
      }
    }
  });

  return socket;
}

function rememberId(id) {
  state.seen.add(id);
  if (state.seen.size > MAX_SEEN_IDS) {
    state.seen.delete(state.seen.values().next().value);
  }
}

function waitForConnection(socket) {
  if (socket.connected) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error("timeout"));
    }, ACK_TIMEOUT_MS);
    const onConnect = () => { cleanup(); resolve(); };
    const cleanup = () => { clearTimeout(timer); socket.off("connect", onConnect); };
    socket.on("connect", onConnect);
    setStatus("connecting", "Connecting…");
    socket.connect();
  });
}

// ---------- actions ----------

function validateJoinForm() {
  const name = els.name.value.trim();
  const room = els.room.value.trim();
  const passphrase = els.passphrase.value;

  for (const el of [els.name, els.room, els.passphrase]) el.removeAttribute("aria-invalid");

  if (!name) return { field: els.name, error: "Enter a display name." };
  if (name.length > MAX_NAME_LENGTH) return { field: els.name, error: "Display name is too long." };
  if (!ROOM_ID_PATTERN.test(room)) {
    return { field: els.room, error: "Room ID must be 6–64 characters: letters, numbers, - or _." };
  }
  if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
    return { field: els.passphrase, error: `Passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters.` };
  }
  return { name, room, passphrase };
}

async function handleJoin(event) {
  event.preventDefault();
  showError(els.joinError, "");

  const input = validateJoinForm();
  if (input.error) {
    input.field.setAttribute("aria-invalid", "true");
    input.field.focus();
    showError(els.joinError, input.error);
    return;
  }

  setBusy(els.joinBtn, true, "Deriving key…");
  try {
    if (!window.isSecureContext || !globalThis.crypto?.subtle) {
      throw new Error("Encryption requires HTTPS (or localhost). Open the app over a secure connection.");
    }
    const { key, fingerprint } = await deriveRoomKey(input.passphrase, input.room);

    setBusy(els.joinBtn, true, "Connecting…");
    const socket = ensureSocket();
    try {
      await waitForConnection(socket);
    } catch {
      throw new Error("Couldn't reach the server. Check your connection and try again.");
    }

    const res = await emitWithAck("join", { room: input.room });
    if (!res.ok) throw new Error(errorText(res.error));

    state.key = key;
    state.room = input.room;
    state.name = input.name;
    state.seen.clear();
    storageSet("secure-chat:name", input.name);
    history.replaceState(null, "", `#room=${encodeURIComponent(input.room)}`);

    els.passphrase.value = "";
    els.roomTitle.textContent = input.room;
    els.fingerprint.textContent = fingerprint;
    setMemberCount(res.count);
    clearMessages();
    const hint = document.createElement("p");
    hint.className = "notice";
    hint.textContent = `Joined as ${input.name}. Compare the safety code with others to confirm you share the same passphrase.`;
    els.messages.prepend(hint);
    document.body.classList.add("in-room");

    els.joinView.hidden = true;
    els.chatView.hidden = false;
    updateSendButton();
    els.messageInput.focus();
  } catch (err) {
    showError(els.joinError, err.message);
  } finally {
    setBusy(els.joinBtn, false, "Join room");
  }
}

async function handleSend(event) {
  event?.preventDefault();
  const text = els.messageInput.value.trim();
  if (!text || !state.key) return;
  showError(els.composerError, "");

  const { key, room } = state;
  els.sendBtn.disabled = true;
  try {
    const { envelope, message } = await encryptMessage(key, room, { name: state.name, text });
    const res = await emitWithAck("message", envelope);
    if (!res.ok) throw new Error(errorText(res.error));
    rememberId(message.id);
    renderMessage(message, true);
    els.messageInput.value = "";
    autosize();
  } catch (err) {
    showError(els.composerError, err instanceof RangeError ? "That message is too long." : err.message);
  } finally {
    updateSendButton();
    els.messageInput.focus();
  }
}

function handleLeave() {
  if (state.socket) {
    state.socket.emit("leave", null);
    state.socket.disconnect();
    state.socket = null;
  }
  state.key = null;
  state.room = null;
  state.seen.clear();
  clearMessages();
  showError(els.composerError, "");
  els.messageInput.value = "";
  setStatus("offline", "Not connected");
  document.body.classList.remove("in-room");
  els.chatView.hidden = true;
  els.joinView.hidden = false;
  els.passphrase.focus();
}

async function handleCopyLink() {
  const link = roomLink(state.room);
  const label = els.copyLink.querySelector("span");
  try {
    await navigator.clipboard.writeText(link);
    label.textContent = "Copied";
  } catch {
    window.prompt("Copy this room link (the passphrase is not included):", link);
  }
  setTimeout(() => { label.textContent = "Copy link"; }, 2000);
}

function autosize() {
  els.messageInput.style.height = "auto";
  els.messageInput.style.height = `${els.messageInput.scrollHeight}px`;
}

// ---------- wiring ----------

els.joinForm.addEventListener("submit", handleJoin);
els.composer.addEventListener("submit", handleSend);
els.leaveBtn.addEventListener("click", handleLeave);
els.copyLink.addEventListener("click", handleCopyLink);

els.generateRoom.addEventListener("click", () => {
  els.room.value = randomRoomId();
  els.room.removeAttribute("aria-invalid");
});

els.togglePass.addEventListener("click", () => {
  const show = els.passphrase.type === "password";
  els.passphrase.type = show ? "text" : "password";
  els.togglePass.setAttribute("aria-pressed", String(show));
  els.togglePass.setAttribute("aria-label", show ? "Hide passphrase" : "Show passphrase");
});

els.messageInput.addEventListener("input", () => {
  autosize();
  updateSendButton();
});
els.messageInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey && !e.isComposing) {
    e.preventDefault();
    if (!els.sendBtn.disabled) handleSend();
  }
});

els.name.value = storageGet("secure-chat:name") ?? "";
els.room.value = roomFromLocation() || randomRoomId();
(els.name.value ? els.passphrase : els.name).focus();
