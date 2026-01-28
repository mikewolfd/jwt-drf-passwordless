"""
Django signals for external 2FA webhook events.

These signals are fired when webhook events are received from external
2FA providers like Telnyx or Twilio. Connect to these signals to react
to verification delivery events.

Example usage:
    from django.dispatch import receiver
    from jwt_drf_passwordless.external_2fa.signals import verification_webhook_received

    @receiver(verification_webhook_received)
    def handle_verification_event(sender, event, **kwargs):
        if event.event_type == WebhookEventType.DELIVERED:
            # Log successful delivery
            logger.info(f"Verification delivered to {event.phone_number}")
        elif event.event_type == WebhookEventType.FAILED:
            # Alert on delivery failure
            logger.error(f"Verification failed for {event.phone_number}")
"""

from django.dispatch import Signal

# Fired when a webhook event is received from an external 2FA provider
# Provides: event (WebhookEvent), provider (str)
verification_webhook_received = Signal()

# Fired when verification is successfully delivered
# Provides: event (WebhookEvent), phone_number (str)
verification_delivered = Signal()

# Fired when verification delivery fails
# Provides: event (WebhookEvent), phone_number (str), error (str)
verification_delivery_failed = Signal()
