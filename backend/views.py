from django.http import HttpResponse


def index(request):
    msg = "Welcome to anitube-website-api"

    return HttpResponse(msg)
