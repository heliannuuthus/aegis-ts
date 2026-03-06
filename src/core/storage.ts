import type { StorageAdapter } from '@/types';

export class BrowserStorageAdapter implements StorageAdapter {
  async getItem(key: string): Promise<string | null> {
    try { return localStorage.getItem(key); } catch { return null; }
  }
  async setItem(key: string, value: string): Promise<void> {
    try { localStorage.setItem(key, value); } catch { /* noop */ }
  }
  async removeItem(key: string): Promise<void> {
    try { localStorage.removeItem(key); } catch { /* noop */ }
  }
}

export class MemoryStorageAdapter implements StorageAdapter {
  private store = new Map<string, string>();

  async getItem(key: string): Promise<string | null> {
    return this.store.get(key) ?? null;
  }
  async setItem(key: string, value: string): Promise<void> {
    this.store.set(key, value);
  }
  async removeItem(key: string): Promise<void> {
    this.store.delete(key);
  }
  clear(): void {
    this.store.clear();
  }
}
