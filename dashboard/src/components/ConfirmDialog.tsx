import { AlertTriangle, X } from 'lucide-react';
import { useEffect, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';

interface ConfirmDialogProps {
  open: boolean;
  title: string;
  message: string;
  confirmLabel?: string;
  confirmVariant?: 'primary' | 'danger';
  onConfirm: (reason?: string) => void;
  onCancel: () => void;
  showReason?: boolean;
  children?: ReactNode;
  confirmDisabled?: boolean;
}

export default function ConfirmDialog({
  open,
  title,
  message,
  confirmLabel = 'Confirm',
  confirmVariant = 'primary',
  onConfirm,
  onCancel,
  showReason = false,
  children,
  confirmDisabled = false,
}: ConfirmDialogProps) {
  const [reason, setReason] = useState('');
  const dialogRef = useRef<HTMLDivElement>(null);
  const confirmBtnRef = useRef<HTMLButtonElement>(null);
  const reasonInputRef = useRef<HTMLTextAreaElement>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (open) {
      previousFocusRef.current = document.activeElement as HTMLElement | null;
      setReason('');
      document.body.classList.add('modal-open');
      window.setTimeout(() => {
        if (showReason) reasonInputRef.current?.focus();
        else confirmBtnRef.current?.focus();
      }, 50);
    }
    return () => {
      document.body.classList.remove('modal-open');
      previousFocusRef.current?.focus();
    };
  }, [open, showReason]);

  useEffect(() => {
    if (!open) return;
    const handleKeyDown = (e: globalThis.KeyboardEvent) => {
      if (e.key === 'Escape') onCancel();
      if (e.key === 'Tab' && dialogRef.current) {
        const focusable = Array.from(dialogRef.current.querySelectorAll<HTMLElement>(
          'button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])',
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
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [open, onCancel]);

  const handleKeyDown = (e: KeyboardEvent) => {
    if (e.key === 'Enter' && !showReason) {
      onConfirm();
    }
  };

  if (!open) return null;

  const handleConfirm = () => {
    if (showReason) {
      onConfirm(reason);
    } else {
      onConfirm();
    }
  };

  return (
    <div className="modal-overlay" role="presentation">
      <div className="modal" ref={dialogRef} onKeyDown={handleKeyDown} role="dialog" aria-modal="true" aria-labelledby="confirm-dialog-title" aria-describedby="confirm-dialog-message">
        <div className="modal__header">
          <span className={`modal__icon modal__icon--${confirmVariant}`}><AlertTriangle size={18} /></span>
          <div>
            <h2 className="modal__title" id="confirm-dialog-title">{title}</h2>
            <p className="modal__message" id="confirm-dialog-message">{message}</p>
          </div>
          <button className="modal__close" type="button" onClick={onCancel} aria-label="Close dialog"><X size={17} /></button>
        </div>
        {children}
        {showReason && (
          <div className="modal__field">
            <label htmlFor="deny-reason" className="modal__label">Reason (required for deny)</label>
            <textarea
              id="deny-reason"
              ref={reasonInputRef}
              className="modal__textarea"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Enter reason..."
              rows={3}
            />
          </div>
        )}
        <div className="modal__actions">
          <button className="btn btn--ghost" onClick={onCancel} aria-label="Cancel">
            Cancel
          </button>
          <button
            ref={confirmBtnRef}
            className={`btn btn--${confirmVariant}`}
            onClick={handleConfirm}
            disabled={confirmDisabled || (showReason && !reason.trim())}
            aria-label={confirmLabel}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
