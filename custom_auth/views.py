from django.views.generic import TemplateView
from django.views.generic import View
from django.shortcuts import render


# Create your views here.
class SignupView(View):
    template_name = 'signup.html'

    def get(self, request):
        context = {}
        return render(request, self.template_name)

    def post(self, request, **kwargs):
        pass


class LoginView(View):
    template_name = 'login.html'

    def get(self, request):
        context = {}
        return render(request, self.template_name)

    def post(self, request, **kwargs):
        pass


class ProfileView(TemplateView):
    login_url = '/login'
    template_name = 'profile.html'
