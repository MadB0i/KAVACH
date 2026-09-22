import { X } from 'lucide-react';
import { useEffect, useRef, type ReactNode } from 'react';

interface DetailDrawerProps {
  open: boolean;
  title: string;
  onClose: () => void;
  children: ReactNode;
}

export default function DetailDrawer({ open, title, onClose, children }: DetailDrawerProps) {
  const drawerRef = useRef<HTMLDivElement>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) return;
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
      if (e.key === 'Tab' && drawerRef.current) {
        const focusable = Array.from(drawerRef.current.querySelectorAll<HTMLElement>(
          'button:not([disabled]), a[href], input:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
        ));
        if (focusable.length === 0) return;
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last?.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first?.focus();
        }
      }
    };
    document.addEventListener('keydown', handleKey);
    return () => {
      document.removeEventListener('keydown', handleKey);
      document.body.classList.remove('modal-open');
      previousFocusRef.current?.focus();
    };
  }, [open, onClose]);

  useEffect(() => {
    if (open) {
      previousFocusRef.current = document.activeElement as HTMLElement | null;
      document.body.classList.add('modal-open');
      drawerRef.current?.focus();
    }
  }, [open]);

  if (!open) return null;

  return (
    <>
      <div className="drawer-overlay" onClick={onClose} aria-hidden="true" />
      <div
        className="drawer"
        ref={drawerRef}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
      >
        <div className="drawer__header">
          <h2 className="drawer__title">{title}</h2>
          <button className="drawer__close" onClick={onClose} aria-label="Close drawer">
            <X size={17} />
          </button>
        </div>
        <div className="drawer__body">{children}</div>
      </div>
    </>
  );
}
