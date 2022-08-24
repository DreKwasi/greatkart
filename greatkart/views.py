from django.http import HttpResponse
from django.shortcuts import render
from accounts.models import Account
from store.models import *


def home(request):
    products = Product.objects.all().filter(is_available=True)
    context = {"products": products}
    return render(request, "home.html", context)
