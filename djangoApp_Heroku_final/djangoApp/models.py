from django.db import models
from django.contrib.auth import get_user_model

class Page(models.Model):
    id = models.AutoField(primary_key = True)
    title = models.CharField(max_length=256)
    description = models.CharField(max_length=1024)
    href = models.URLField(max_length=2084)
    date_published = models.DateField(auto_now = True)
    feed = models.ForeignKey(
        'Feed',
        on_delete = models.CASCADE
    )
    user = models.ForeignKey(
        get_user_model(),
        on_delete = models.CASCADE
    )

class Feed(models.Model):
    id = models.AutoField(primary_key = True)
    title = models.CharField(max_length=256)
    description = models.CharField(max_length=1024)
    href = models.URLField(max_length=2084)
    rss = models.URLField(max_length =2084)
    user = models.ForeignKey(
        get_user_model(),
        on_delete = models.CASCADE,
    )
