from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model
from django.template.loader import get_template
from django.http import HttpResponseServerError

import feedparser
from hashlib import sha256
import logging

from .mail import send_mail
from .models import Feed, Page
from .forms import UserForm

logger = logging.getLogger(__name__)

User = get_user_model()

def indexα(request):
    return render(request, 'indexα.html')

def indexβ(request, user_id):
    user_unique = User.objects.get(id = int(user_id))
    pages = Page.objects.filter(user = user_unique)
    indexβ_element = {
        'pages':pages,
        'user_id':user_id,
        'username':user_unique.username
        }
    return render(request, 'indexβ.html', indexβ_element)

def post(request, user_id):
    if request.method != 'POST':
        return redirect("/" + str(user_id) + "/indexβ")
    try:
        rss = feedparser.parse(request.POST.get('url'))
        print(rss)
    except Exception as e:
        logger.exception(e)
    if rss.entries: 
        try:
            user_unique = User.objects.get(id = int(user_id))
            feed = Feed.objects.create(
                title = rss.feed.title,
                description = rss.feed.subtitle,
                href = request.POST.get('url'),
                user = user_unique
            )
            feed.save()
            return redirect("/" + str(user_id) + "/indexβ")
        except Exception as e:
            logger.exception(e)
            raise HttpResponseServerError()
    return redirect("/" + str(user_id) + "/indexβ")

def search(request, user_id):
    user_unique = User.objects.get(id = int(user_id))
    pages_search = Page.objects.filter(user = user_unique, title__icontains = request.GET.get("q"))
    search_keyword = request.GET.get("q")
    if pages_search.first() is None:
        nullmessage = "検索キーワードに一致する記事はありません"
        search_element = {
            'user_id':user_id,
            'username':user_unique.username,
            'search_keyword':search_keyword,
            'nullmessage':nullmessage
        }
        return render(request, 'search.html', search_element)
    else:
        search_element = {
            'user_id':user_id,
            'username':user_unique.username,
            'search_keyword':search_keyword,
            'pages_search':pages_search
        }
        return render(request, 'search.html', search_element)

def setting(request, user_id):
    user_unique = User.objects.get(id = int(user_id))
    feeds = Feed.objects.filter(user = user_unique)
    setting_element ={
        'user_id':user_id,
        'username':user_unique.username,
        'feeds':feeds,
    }
    return render(request, 'setting.html', setting_element)

def delete_feed(request, user_id):
    if request.method == "POST" and request.POST.get('id'):
        user_unique = User.objects.get(id = int(user_id))
        feed = Feed.objects.filter(id = request.POST.get('id'), user = user_unique)
        feed.delete()
        return redirect('/' + str(user_id) + '/setting')

def login_view(request):
    if request.method != 'POST':
        return redirect('/')
    user_check = authenticate(request, username = request.POST.get('username'), password = request.POST.get('password'))
    if user_check is None:
        return redirect('/accounts/login')
    else:
        login(request, user_check)
        user = User.objects.get(username = request.POST.get('username'))
        user_id = user.id
        return redirect('/' + str(user_id) + '/indexβ')

def create_user_view(request):
    form = UserForm()
    return render(request, 'create_user_view.html', {'form':form})

def create_user(request):
    if request.method == 'POST':
        form = UserForm(request.POST)
        if form.is_valid():
            token = sha256(('eqd131' + str(request.POST.get('username').encode('utf-8')) + ": " + str(request.POST.get('email').encode('utf-8'))).encode('utf-8')).hexdigest()
            email_html = get_template('email.html').render(
                {
                    'username':request.POST.get('username'),
                    'email':request.POST.get('email'),
                    'token':token
                }
            )
        user = User.objects.create_user(
            username = request.POST.get('username'),
            email = request.POST.get('email'),
            password = request.POST.get('password'),
            is_active = False
        )
        user.save()
        send_mail(request.POST.get('email'), "確認用メール", email_html)
        return redirect("/accounts/login")
    return redirect("/create_user_view")

def check_mail(request):
    user = User.objects.get(username = request.GET.get('username'))
    token = sha256(('eqd131' + str(user.username.encode('utf-8')) + ": " + str(user.email.encode('utf-8'))).encode('utf-8')).hexdigest()

    if token == request.GET.get('token'):
        user.is_active = True
        user.save()
        return redirect("/")
    else:
        return redirect("/?failed=true")

@login_required
def logout_view(request):
    logout(request)
    return redirect('/')
