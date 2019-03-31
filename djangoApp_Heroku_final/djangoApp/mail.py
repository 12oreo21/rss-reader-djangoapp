import os
import requests

key =os.environ['MAILGUN_API_KEY']

def send_mail(to, subject, html):
    request_url = "https://api.mailgun.net/v3/reonanjo.work/messages"
    request = requests.post(request_url, auth=('api', key), data={
        'from':'noreply@reonanjo.work',
        'to':to,
        'subject':subject,
        'html':html
    } )
