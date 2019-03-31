import os
import django
from celery import Celery
from celery.schedules import crontab
import feedparser
import logging


logger = logging.getLogger(__name__)

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'djangoApp.settings')

app = Celery('djangoApp')

app.config_from_object('django.conf:settings', namespace='CELERY')

app.conf.update({
    'CELERYBEAT_SCHEDULE':{
        'echo':{
            'task':'celery_task.fetch',
            'schedule':crontab(minute='*/1')
        }
    }
})

django.setup()

from .models import Page, Feed

@app.task(name='celery_task.fetch')
def fetch():
    feeds = Feed.objects.all()
    for feed in feeds:
        try:
            rss = feedparser.parse(feed.href)
            for entry in rss.entries:
                try:
                    page_exists = Page.objects.get(href=entry.link)
                except Page.DoesNotExist:
                    page = Page.objects.create(
                    title = entry.title,
                    href = entry.link,
                    feed = feed,
                    user = feed.user
                    )
                    page.save()
        except Exception as e:
            logger.exception(e)
