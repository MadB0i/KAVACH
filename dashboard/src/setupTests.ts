import '@testing-library/jest-dom';
import { vi } from 'vitest';

Object.defineProperty(window, 'scrollTo', {
  configurable: true,
  value: vi.fn(),
  writable: true,
});
