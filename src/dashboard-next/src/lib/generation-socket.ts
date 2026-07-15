export interface ManagedSocket {
  readyState: number;
  onopen: ((event: Event) => void) | null;
  onmessage: ((event: MessageEvent) => void) | null;
  onclose: ((event: CloseEvent) => void) | null;
  onerror: ((event: Event) => void) | null;
  close: () => void;
}

export interface GenerationSocketOptions {
  createSocket: () => ManagedSocket;
  onMessage: (data: unknown, generation: number) => void;
  onSynchronizedChange: (synchronized: boolean) => void;
  onDisconnected?: () => void;
  backoffMs?: readonly number[];
  fullStateTimeoutMs?: number;
  setTimer?: (callback: () => void, delay: number) => ReturnType<typeof setTimeout>;
  clearTimer?: (timer: ReturnType<typeof setTimeout>) => void;
}

export interface FallbackPollTicket {
  generation: number;
  controller: AbortController;
}

/**
 * Generation guard for HTTP fallback snapshots. Starting or invalidating a
 * poll aborts its predecessor, and only the latest ticket may publish state.
 */
export class FallbackPollCoordinator {
  private generation = 0;
  private active: FallbackPollTicket | null = null;

  begin(): FallbackPollTicket {
    this.invalidate();
    const ticket = { generation: this.generation, controller: new AbortController() };
    this.active = ticket;
    return ticket;
  }

  invalidate(): void {
    this.generation++;
    this.active?.controller.abort();
    this.active = null;
  }

  isCurrent(ticket: FallbackPollTicket): boolean {
    return this.active === ticket
      && ticket.generation === this.generation
      && !ticket.controller.signal.aborted;
  }

  complete(ticket: FallbackPollTicket): void {
    if (this.active === ticket) this.active = null;
  }
}

/**
 * Own exactly one main-channel socket and one retry timer. Every callback is
 * tagged with its connection generation so a closing/replaced socket cannot
 * mutate current dashboard state.
 */
export class GenerationSocketController {
  private readonly options: Required<Pick<GenerationSocketOptions, 'backoffMs' | 'fullStateTimeoutMs' | 'setTimer' | 'clearTimer'>> & GenerationSocketOptions;
  private socket: ManagedSocket | null = null;
  private retryTimer: ReturnType<typeof setTimeout> | null = null;
  private fullStateTimer: ReturnType<typeof setTimeout> | null = null;
  private generation = 0;
  private retryIndex = 0;
  private running = false;
  private synchronized = false;

  constructor(options: GenerationSocketOptions) {
    this.options = {
      ...options,
      backoffMs: options.backoffMs ?? [1_000, 2_000, 4_000, 8_000, 16_000, 30_000],
      fullStateTimeoutMs: options.fullStateTimeoutMs ?? 5_000,
      setTimer: options.setTimer ?? ((callback, delay) => setTimeout(callback, delay)),
      clearTimer: options.clearTimer ?? (timer => clearTimeout(timer)),
    };
  }

  start(): void {
    if (this.running) return;
    this.running = true;
    this.connect();
  }

  stop(): void {
    if (!this.running) return;
    this.running = false;
    this.generation++;
    this.clearRetry();
    this.clearFullStateDeadline();
    const socket = this.socket;
    this.socket = null;
    if (socket) {
      socket.onopen = null;
      socket.onmessage = null;
      socket.onclose = null;
      socket.onerror = null;
      socket.close();
    }
    this.setSynchronized(false);
  }

  markSynchronized(generation: number): boolean {
    if (!this.running || generation !== this.generation || !this.socket) return false;
    this.clearFullStateDeadline();
    this.retryIndex = 0;
    this.setSynchronized(true);
    return true;
  }

  isSynchronized(): boolean {
    return this.synchronized;
  }

  currentGeneration(): number {
    return this.generation;
  }

  private connect(): void {
    if (!this.running || this.socket || this.retryTimer) return;
    const generation = ++this.generation;
    let socket: ManagedSocket;
    try {
      socket = this.options.createSocket();
    } catch {
      this.scheduleRetry();
      return;
    }
    this.socket = socket;

    socket.onopen = event => {
      if (!this.isCurrent(socket, generation)) return;
      this.clearFullStateDeadline();
      this.fullStateTimer = this.options.setTimer(() => {
        if (!this.isCurrent(socket, generation) || this.synchronized) return;
        socket.close();
      }, this.options.fullStateTimeoutMs);
      void event;
    };
    socket.onmessage = event => {
      if (!this.isCurrent(socket, generation)) return;
      this.options.onMessage(event.data, generation);
    };
    socket.onerror = () => {
      if (this.isCurrent(socket, generation)) socket.close();
    };
    socket.onclose = () => {
      if (!this.isCurrent(socket, generation)) return;
      this.socket = null;
      this.clearFullStateDeadline();
      this.setSynchronized(false);
      this.options.onDisconnected?.();
      this.scheduleRetry();
    };
  }

  private isCurrent(socket: ManagedSocket, generation: number): boolean {
    return this.running && this.socket === socket && this.generation === generation;
  }

  private scheduleRetry(): void {
    if (!this.running || this.retryTimer || this.socket) return;
    const delays = this.options.backoffMs;
    const delay = delays[Math.min(this.retryIndex, delays.length - 1)];
    this.retryIndex++;
    this.retryTimer = this.options.setTimer(() => {
      this.retryTimer = null;
      this.connect();
    }, delay);
  }

  private setSynchronized(value: boolean): void {
    if (this.synchronized === value) return;
    this.synchronized = value;
    this.options.onSynchronizedChange(value);
  }

  private clearRetry(): void {
    if (!this.retryTimer) return;
    this.options.clearTimer(this.retryTimer);
    this.retryTimer = null;
  }

  private clearFullStateDeadline(): void {
    if (!this.fullStateTimer) return;
    this.options.clearTimer(this.fullStateTimer);
    this.fullStateTimer = null;
  }
}
