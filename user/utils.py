from django.core.mail import EmailMessage
import os

class Utils:
    @staticmethod
    def send_email(data):
        email = EmailMessage(
            subject=data['subject'],
            body=data['body'],
            from_email=os.environ['EMAIL_FROM'],
            to=[data['email_to']]
        )
        email.send()