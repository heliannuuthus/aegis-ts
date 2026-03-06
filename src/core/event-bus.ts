import type { AuthEvent, AuthEventType, AuthEventListener } from '@/types';

export class EventBus {
  private listeners = new Map<AuthEventType, Set<AuthEventListener>>();

  emit(type: AuthEventType, data?: unknown): void {
    const event: AuthEvent = { type, data };
    this.listeners.get(type)?.forEach((fn) => fn(event));
  }

  on(event: AuthEventType, listener: AuthEventListener): () => void {
    if (!this.listeners.has(event)) this.listeners.set(event, new Set());
    this.listeners.get(event)!.add(listener);
    return () => this.off(event, listener);
  }

  off(event: AuthEventType, listener: AuthEventListener): void {
    this.listeners.get(event)?.delete(listener);
  }
}
