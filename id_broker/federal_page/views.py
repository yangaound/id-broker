from django.shortcuts import render

# Create your views here.


def render_federal_signin_page(req):
    return render(req, "federal_signin.html")


def render_federal_oauth2_signin_error_page(req):
    return render(req, "oauth2_signin_error.html")
