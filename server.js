// Entry point: `npm start` (Node 22+).
import { createChatServer } from "./src/server.js";

const PORT = Number.parseInt(process.env.PORT ?? "3000", 10);
const HOST = process.env.HOST ?? "0.0.0.0";
const allowedOrigins = (process.env.ALLOWED_ORIGINS ?? "")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

const { httpServer, io } = createChatServer({ allowedOrigins });

httpServer.listen(PORT, HOST, () => {
  console.log(`Secure Chat listening on http://localhost:${PORT}`);
});

const shutdown = () => io.close(() => process.exit(0));
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
