# tasks.py - Background tasks for payment processing

from celery import shared_task
from django.conf import settings
from django.utils import timezone
from django.core.mail import send_mail
import requests
import logging
from datetime import timedelta
from .models import PaymentSession, Transaction, WebhookLog

logger = logging.getLogger('payment_gateway')


@shared_task(bind=True, max_retries=3)
def send_webhook_notification(self, payment_session_id, transaction_id):
    """Send webhook notification to merchant"""
    try:
        payment_session = PaymentSession.objects.get(id=payment_session_id)
        transaction = Transaction.objects.get(id=transaction_id)
        
        if not payment_session.webhook_url:
            logger.info(f"No webhook URL configured for session {payment_session.session_id}")
            return
        
        payload = {
            'session_id': str(payment_session.session_id),
            'status': payment_session.status,
            'amount': float(payment_session.amount),
            'currency': payment_session.currency,
            'transaction_id': str(transaction.transaction_id),
            'external_transaction_id': transaction.external_transaction_id,
            'completed_at': payment_session.completed_at.isoformat() if payment_session.completed_at else None,
            'metadata': payment_session.metadata,
            'timestamp': timezone.now().isoformat()
        }
        
        response = requests.post(
            payment_session.webhook_url,
            json=payload,
            timeout=10,
            headers={
                'Content-Type': 'application/json',
                'User-Agent': 'Nextremitly-Webhook/1.0'
            }
        )
        
        # Log webhook attempt
        webhook_log = WebhookLog.objects.create(
            payment_session=payment_session,
            webhook_url=payment_session.webhook_url,
            payload=payload,
            response_status=response.status_code,
            response_body=response.text[:1000],  # Limit response body length
            success=response.status_code == 200,
            retry_count=self.request.retries
        )
        
        if response.status_code != 200:
            logger.warning(f"Webhook failed with status {response.status_code} for session {payment_session.session_id}")
            raise Exception(f"Webhook returned status {response.status_code}")
        
        logger.info(f"Webhook sent successfully for session {payment_session.session_id}")
        return True
        
    except Exception as exc:
        logger.error(f"Webhook failed for session {payment_session_id}: {str(exc)}")
        
        # Retry with exponential backoff
        if self.request.retries < self.max_retries:
            countdown = 2 ** self.request.retries * 60  # 1, 2, 4 minutes
            raise self.retry(exc=exc, countdown=countdown)
        
        # Final failure - log it
        WebhookLog.objects.create(
            payment_session_id=payment_session_id,
            webhook_url=payment_session.webhook_url if 'payment_session' in locals() else 'unknown',
            payload={},
            success=False,
            retry_count=self.request.retries
        )
        
        return False


@shared_task
def send_payment_notification_email(user_id, transaction_id, notification_type):
    """Send email notifications for payment events"""
    try:
        from .models import CustUser
        
        user = CustUser.objects.get(id=user_id)
        transaction = Transaction.objects.get(id=transaction_id)
        
        if notification_type == 'payment_successful':
            subject = 'Payment Successful - Nextremitly'
            message = f"""
            Dear {user.nom_complet},
            
            Your payment has been processed successfully.
            
            Transaction Details:
            - Amount: {transaction.amount} {transaction.currency}
            - Transaction ID: {transaction.transaction_id}
            - Date: {transaction.completed_at.strftime('%Y-%m-%d %H:%M:%S')}
            - Merchant: {transaction.merchant.business_name}
            
            Thank you for using Nextremitly!
            
            Best regards,
            The Nextremitly Team
            """
            
        elif notification_type == 'payment_failed':
            subject = 'Payment Failed - Nextremitly'
            message = f"""
            Dear {user.nom_complet},
            
            Unfortunately, your payment could not be processed.
            
            Transaction Details:
            - Amount: {transaction.amount} {transaction.currency}
            - Transaction ID: {transaction.transaction_id}
            - Reason: {transaction.failure_reason}
            - Date: {transaction.created_at.strftime('%Y-%m-%d %H:%M:%S')}
            
            Please try again or contact support if the issue persists.
            
            Best regards,
            The Nextremitly Team
            """
        
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False
        )
        
        logger.info(f"Email notification sent to {user.email} for transaction {transaction.transaction_id}")
        return True
        
    except Exception as exc:
        logger.error(f"Failed to send email notification: {str(exc)}")
        return False


@shared_task
def process_bank_api_response(transaction_id, bank_response):
    """Process response from bank API"""
    try:
        transaction = Transaction.objects.get(id=transaction_id)
        
        if bank_response.get('success'):
            transaction.status = 'completed'
            transaction.external_transaction_id = bank_response.get('transaction_id')
            transaction.completed_at = timezone.now()
            
            # Update payment session
            payment_session = transaction.payment_session
            payment_session.status = 'completed'
            payment_session.completed_at = timezone.now()
            payment_session.save()
            
            # Send notifications
            send_webhook_notification.delay(payment_session.id, transaction.id)
            send_payment_notification_email.delay(
                transaction.sender.id, 
                transaction.id, 
                'payment_successful'
            )
            
        else:
            transaction.status = 'failed'
            transaction.failure_reason = bank_response.get('error', 'Payment failed')
            
            # Update payment session
            payment_session = transaction.payment_session
            payment_session.status = 'failed'
            payment_session.save()
            
            # Send failure notification
            send_payment_notification_email.delay(
                transaction.sender.id, 
                transaction.id, 
                'payment_failed'
            )
        
        transaction.provider_response = bank_response
        transaction.save()
        
        logger.info(f"Bank API response processed for transaction {transaction.transaction_id}")
        return True
        
    except Exception as exc:
        logger.error(f"Failed to process bank API response: {str(exc)}")
        return False


@shared_task
def cleanup_expired_sessions():
    """Clean up expired payment sessions"""
    try:
        expired_time = timezone.now() - timedelta(hours=24)
        
        # Mark expired sessions
        expired_sessions = PaymentSession.objects.filter(
            expires_at__lt=timezone.now(),
            status__in=['pending', 'authenticated', 'wallet_selected', 'otp_sent']
        )
        
        count = expired_sessions.update(status='expired')
        
        # Delete old expired sessions (older than 30 days)
        old_sessions = PaymentSession.objects.filter(
            status='expired',
            created_at__lt=timezone.now() - timedelta(days=30)
        )
        
        deleted_count = old_sessions.count()
        old_sessions.delete()
        
        logger.info(f"Marked {count} sessions as expired, deleted {deleted_count} old sessions")
        return {'expired': count, 'deleted': deleted_count}
        
    except Exception as exc:
        logger.error(f"Failed to cleanup expired sessions: {str(exc)}")
        return False


@shared_task
def cleanup_expired_otps():
    """Clean up expired OTP codes"""
    try:
        from .models import PaymentOTP, OTP_User
        
        # Delete expired payment OTPs
        payment_otps_deleted = PaymentOTP.objects.filter(
            created_at__lt=timezone.now() - timedelta(minutes=30)
        ).delete()[0]
        
        # Delete expired user OTPs
        user_otps_deleted = OTP_User.objects.filter(
            created_at__lt=timezone.now() - timedelta(minutes=30)
        ).delete()[0]
        
        logger.info(f"Deleted {payment_otps_deleted} payment OTPs and {user_otps_deleted} user OTPs")
        return {'payment_otps': payment_otps_deleted, 'user_otps': user_otps_deleted}
        
    except Exception as exc:
        logger.error(f"Failed to cleanup expired OTPs: {str(exc)}")
        return False


@shared_task
def generate_daily_reports():
    """Generate daily transaction reports"""
    try:
        from django.db.models import Sum, Count, Q
        from datetime import date
        
        today = date.today()
        yesterday = today - timedelta(days=1)
        
        # Calculate daily metrics
        daily_stats = Transaction.objects.filter(
            created_at__date=yesterday
        ).aggregate(
            total_transactions=Count('id'),
            successful_transactions=Count('id', filter=Q(status='completed')),
            failed_transactions=Count('id', filter=Q(status='failed')),
            total_volume=Sum('amount', filter=Q(status='completed')),
            total_fees=Sum('fee_amount', filter=Q(status='completed'))
        )
        
        # Get top merchants by transaction volume
        top_merchants = Transaction.objects.filter(
            created_at__date=yesterday,
            status='completed'
        ).values('merchant__business_name').annotate(
            volume=Sum('amount'),
            count=Count('id')
        ).order_by('-volume')[:10]
        
        # Create report
        report = {
            'date': yesterday.isoformat(),
            'stats': daily_stats,
            'top_merchants': list(top_merchants),
            'generated_at': timezone.now().isoformat()
        }
        
        # Send report to admin email
        subject = f'Nextremitly Daily Report - {yesterday}'
        message = f"""
        Daily Transaction Report for {yesterday}
        
        Total Transactions: {daily_stats['total_transactions']}
        Successful: {daily_stats['successful_transactions']}
        Failed: {daily_stats['failed_transactions']}
        Success Rate: {(daily_stats['successful_transactions'] / daily_stats['total_transactions'] * 100):.2f}%
        
        Total Volume: {daily_stats['total_volume']} MRU
        Total Fees Collected: {daily_stats['total_fees']} MRU
        
        Top Merchants by Volume:
        {chr(10).join([f"- {m['merchant__business_name']}: {m['volume']} MRU ({m['count']} transactions)" for m in top_merchants[:5]])}
        
        Full report attached.
        """
        
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            ['admin@nextremitly.com'],  # Replace with actual admin email
            fail_silently=False
        )
        
        logger.info(f"Daily report generated for {yesterday}")
        return report
        
    except Exception as exc:
        logger.error(f"Failed to generate daily report: {str(exc)}")
        return False


@shared_task
def monitor_payment_performance():
    """Monitor payment system performance and alert on issues"""
    try:
        from datetime import datetime
        
        # Check recent payment success rate
        recent_transactions = Transaction.objects.filter(
            created_at__gte=timezone.now() - timedelta(hours=1)
        )
        
        if recent_transactions.count() > 0:
            success_rate = recent_transactions.filter(status='completed').count() / recent_transactions.count()
            
            if success_rate < 0.8:  # Alert if success rate below 80%
                send_mail(
                    'ALERT: Low Payment Success Rate',
                    f'Payment success rate in the last hour is {success_rate:.2%}. Please investigate.',
                    settings.DEFAULT_FROM_EMAIL,
                    ['tech@nextremitly.com'],  # Replace with actual tech team email
                    fail_silently=False
                )
                
                logger.warning(f"Low payment success rate detected: {success_rate:.2%}")
        
        # Check for stuck transactions
        stuck_transactions = Transaction.objects.filter(
            status='processing',
            created_at__lt=timezone.now() - timedelta(minutes=10)
        )
        
        if stuck_transactions.exists():
            send_mail(
                'ALERT: Stuck Transactions Detected',
                f'{stuck_transactions.count()} transactions have been in processing state for over 10 minutes.',
                settings.DEFAULT_FROM_EMAIL,
                ['tech@nextremitly.com'],
                fail_silently=False
            )
            
            logger.warning(f"Found {stuck_transactions.count()} stuck transactions")
        
        return True
        
    except Exception as exc:
        logger.error(f"Failed to monitor payment performance: {str(exc)}")
        return False


# Periodic task configuration (add to your celery.py or settings)
"""
from celery.schedules import crontab

CELERY_BEAT_SCHEDULE = {
    'cleanup-expired-sessions': {
        'task': 'your_app.tasks.cleanup_expired_sessions',
        'schedule': crontab(minute=0, hour='*/6'),  # Every 6 hours
    },
    'cleanup-expired-otps': {
        'task': 'your_app.tasks.cleanup_expired_otps',
        'schedule': crontab(minute='*/30'),  # Every 30 minutes
    },
    'generate-daily-reports': {
        'task': 'your_app.tasks.generate_daily_reports',
        'schedule': crontab(minute=0, hour=6),  # Daily at 6 AM
    },
    'monitor-payment-performance': {
        'task': 'your_app.tasks.monitor_payment_performance',
        'schedule': crontab(minute='*/5'),  # Every 5 minutes
    },
}
"""