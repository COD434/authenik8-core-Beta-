import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Store } from '../../storage/userStorage';

const mockUserStore = {
  findByEmail: vi.fn(),
  create: vi.fn().mockResolvedValue(undefined),
};

beforeEach(() => {
  vi.clearAllMocks();
});

describe('Store', () => {
  let store: Store;

  beforeEach(() => {
    store = new Store(mockUserStore as any);
  });

  describe('register', () => {
    it('throws when a user with that email already exists', async () => {
      mockUserStore.findByEmail.mockResolvedValue({ email: 'test@example.com' });

      await expect(
        store.register('test@example.com', 'password123')
      ).rejects.toThrow('If a record of user exists an email will be sent');

      expect(mockUserStore.create).not.toHaveBeenCalled();
    });

    it('creates the user when email is not taken', async () => {
      mockUserStore.findByEmail.mockResolvedValue(null);

      await store.register('new@example.com', 'password123');

      expect(mockUserStore.create).toHaveBeenCalledWith({
        email: 'new@example.com',
        password: 'password123',
      });
    });

    it('calls findByEmail with the provided email', async () => {
      mockUserStore.findByEmail.mockResolvedValue(null);

      await store.register('check@example.com', 'pass');

      expect(mockUserStore.findByEmail).toHaveBeenCalledWith('check@example.com');
    });
  });
});
