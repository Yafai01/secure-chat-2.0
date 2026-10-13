// Secure Chat relay server.
//
// The server is a blind relay: clients encrypt and decrypt in the browser and
// the server only forwards validated AES-GCM envelopes to the other members
// of the same room. It never receives passphrases, keys or plaintext, and it
// never logs message contents or room IDs.

import express from "express";
import { createServer } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Server } from "socket.io";

import { TokenBucket } from "./rate-limiter.js";
import { validateJoin, validateMessage } from "./validation.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, "..", "public");

/** Upper bound for a single Socket.IO packet (bytes). */
export const MAX_PACKET_BYTES = 16 * 1024;

const DEFAULT_LIMITS = {
  message: { capacity: 10, refillPerSecond: 2 },
  join: { capacity: 5, refillPerSecond: 0.5 },
};

const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join("; ");

function securityHeaders(_req, res, next) {
  res.setHeader("Content-Security-Policy", CONTENT_SECURITY_POLICY);
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  next();
}

/**
 * Builds an origin check for the Socket.IO handshake. Browsers always send an
 * Origin header; requests from other origins are rejected unless explicitly
 * allowed. Requests without an Origin (non-browser clients) are allowed, as
 * they are not subject to cross-site attacks.
 */
function createOriginCheck(allowedOrigins) {
  return (req, callback) => {
    const origin = req.headers.origin;
    if (!origin) return callback(null, true);
    if (allowedOrigins.length > 0) return callback(null, allowedOrigins.includes(origin));
    try {
      callback(null, new URL(origin).host === req.headers.host);
    } catch {
      callback(null, false);
    }
  };
}

function reply(ack, body) {
  if (typeof ack === "function") ack(body);
}

/**
 * Creates (but does not start) the HTTP + Socket.IO server.
 * @param {object} [options]
 * @param {string[]} [options.allowedOrigins]  Extra origins allowed to connect.
 * @param {typeof DEFAULT_LIMITS} [options.limits]  Rate-limit settings.
 * @param {Pick<Console, "log" | "warn">} [options.logger]
 */
export function createChatServer({
  allowedOrigins = [],
  limits = DEFAULT_LIMITS,
  logger = console,
} = {}) {
  const app = express();
  app.disable("x-powered-by");
  app.use(securityHeaders);
  app.use(express.static(PUBLIC_DIR, { index: "index.html" }));
  app.get("/healthz", (_req, res) => res.json({ status: "ok" }));

  const httpServer = createServer(app);
  const io = new Server(httpServer, {
    maxHttpBufferSize: MAX_PACKET_BYTES,
    allowRequest: createOriginCheck(allowedOrigins),
    serveClient: true,
  });

  const roomSize = (room) => io.sockets.adapter.rooms.get(room)?.size ?? 0;
  const announcePresence = (room) => io.to(room).emit("presence", { count: roomSize(room) });

  io.on("connection", (socket) => {
    logger.log(`Client connected (${io.engine.clientsCount} online)`);

    const messageBucket = new TokenBucket(limits.message);
    const joinBucket = new TokenBucket(limits.join);

    socket.on("join", (data, ack) => {
      if (!joinBucket.tryRemove()) return reply(ack, { ok: false, error: "rate_limited" });

      const result = validateJoin(data);
      if (!result.ok) return reply(ack, result);

      const previous = socket.data.room;
      if (previous === result.room) {
        return reply(ack, { ok: true, count: roomSize(result.room) });
      }
      if (previous) {
        socket.leave(previous);
        announcePresence(previous);
      }

      socket.join(result.room);
      socket.data.room = result.room;
      reply(ack, { ok: true, count: roomSize(result.room) });
      announcePresence(result.room);
    });

    socket.on("leave", (_data, ack) => {
      const room = socket.data.room;
      if (room) {
        socket.leave(room);
        socket.data.room = undefined;
        announcePresence(room);
      }
      reply(ack, { ok: true });
    });

    socket.on("message", (data, ack) => {
      const room = socket.data.room;
      if (!room) return reply(ack, { ok: false, error: "not_in_room" });
      if (!messageBucket.tryRemove()) return reply(ack, { ok: false, error: "rate_limited" });

      const result = validateMessage(data);
      if (!result.ok) return reply(ack, result);

      // Relay to everyone else in the same room only. The sender renders its
      // own message locally after this acknowledgement.
      socket.to(room).emit("message", result.message);
      reply(ack, { ok: true });
    });

    socket.on("disconnect", () => {
      const room = socket.data.room;
      if (room) announcePresence(room);
      logger.log("Client disconnected");
    });
  });

  return { app, httpServer, io };
}
