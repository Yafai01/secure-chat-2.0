// Minimal token-bucket rate limiter (one bucket per socket and event type).

export class TokenBucket {
  /**
   * @param {object} options
   * @param {number} options.capacity  Maximum burst size.
   * @param {number} options.refillPerSecond  Tokens added per second.
   * @param {() => number} [options.now]  Clock in ms (injectable for tests).
   */
  constructor({ capacity, refillPerSecond, now = Date.now }) {
    this.capacity = capacity;
    this.refillPerMs = refillPerSecond / 1000;
    this.now = now;
    this.tokens = capacity;
    this.last = now();
  }

  /** @returns {boolean} true if the action is allowed. */
  tryRemove(count = 1) {
    const t = this.now();
    this.tokens = Math.min(this.capacity, this.tokens + (t - this.last) * this.refillPerMs);
    this.last = t;
    if (this.tokens < count) return false;
    this.tokens -= count;
    return true;
  }
}
