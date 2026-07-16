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
}: ConfirmDialogProps) {
  const [reason, setReason] = useState('');
  const dialogRef = useRef<HTMLDivElement>(null);
  const confirmBtnRef = useRef<HTMLButtonElement>(null);
  const reasonInputRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    if (open) {
      setReason('');
      setTimeout(() => confirmBtnRef.current?.focus(), 50);
    }
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const handleKeyDown = (e: globalThis.KeyboardEvent) => {
      if (e.key === 'Escape') onCancel();
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
    <div className="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="confirm-dialog-title">
      <div className="modal" ref={dialogRef} onKeyDown={handleKeyDown}>
        <h2 className="modal__title" id="confirm-dialog-title">{title}</h2>
        <p className="modal__message">{message}</p>
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
            disabled={showReason && !reason.trim()}
            aria-label={confirmLabel}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
