import { ArrowRight, Fingerprint } from 'lucide-react';
import type { AuditEvent } from '../types';
import { formatEventCategory, shortFingerprint, statusVariantForEvent } from '../utils/presentation';
import StatusBadge from './StatusBadge';

interface EventTimelineProps {
  events: AuditEvent[];
  onSelect?: (event: AuditEvent) => void;
  compact?: boolean;
}

export default function EventTimeline({ events, onSelect, compact = false }: EventTimelineProps) {
  return (
    <div className={`event-timeline ${compact ? 'event-timeline--compact' : ''}`} role="list">
      {events.map((event) => {
        const content = (
          <>
            <span className={`event-timeline__rail event-timeline__rail--${statusVariantForEvent(event)}`} aria-hidden="true" />
            <div className="event-timeline__primary">
              <div className="event-timeline__title-row">
                <strong>{formatEventCategory(event.category)}</strong>
                <StatusBadge variant={statusVariantForEvent(event)} label={event.decision || formatEventCategory(event.category)} />
              </div>
              <div className="event-timeline__meta">
                <span>#{event.sequence}</span>
                <span>{event.timestamp ? new Date(event.timestamp).toLocaleString() : 'Time unavailable'}</span>
                <span>{event.operation || 'Operation unavailable'}</span>
              </div>
            </div>
            <div className="event-timeline__correlation">
              <span className="event-timeline__request">{event.request_id || 'No request correlation'}</span>
              {!compact && (
                <span className="event-timeline__fingerprint">
                  <Fingerprint size={12} aria-hidden="true" />
                  {shortFingerprint(event.current_hash)}
                </span>
              )}
            </div>
            {onSelect && <ArrowRight className="event-timeline__arrow" size={15} aria-hidden="true" />}
          </>
        );

        return onSelect ? (
          <button
            key={`${event.sequence}-${event.event_id || event.timestamp}`}
            className="event-timeline__item event-timeline__item--interactive"
            type="button"
            onClick={() => onSelect(event)}
            role="listitem"
            aria-label={`View event ${event.sequence}: ${formatEventCategory(event.category)}`}
          >
            {content}
          </button>
        ) : (
          <div
            key={`${event.sequence}-${event.event_id || event.timestamp}`}
            className="event-timeline__item"
            role="listitem"
          >
            {content}
          </div>
        );
      })}
    </div>
  );
}
