from django.views.generic import TemplateView
from django.views.generic import View
from django.shortcuts import render
from django.contrib.auth.mixins import LoginRequiredMixin
from . import models
from django.contrib.auth import authenticate, login
from django.utils.translation import ugettext_lazy as _
from django.http import HttpResponseRedirect
from django.core.mail import EmailMultiAlternatives
from django.template import loader
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.conf import settings
from django.http import HttpResponse


# Create your views here.
def send_mail(subject, email_template_name,
              context, from_email, to_email, html_email_template_name=None):
    """
    Send a django.core.mail.EmailMultiAlternatives to `to_email`.
    """

    body = loader.render_to_string(email_template_name, context)

    email_message = EmailMultiAlternatives(subject, body, from_email, [to_email])
    if html_email_template_name is not None:
        html_email = loader.render_to_string(html_email_template_name, context)
        email_message.attach_alternative(html_email, 'text/html')

    email_message.send()


class SignupView(View):
    template_name = 'signup.html'
    email_template_name = 'email_verification.html'

    def get(self, request):
        return render(request, self.template_name)

    def post(self, request, **kwargs):
        context = {}
        if request.POST.get('password') != request.POST.get('conform_password'):
            context["error"] = {"conform_password": "Password And Conform Password Does Not Match"}
            return render(request, self.template_name, {"context": context})
        data = {"first_name": request.POST.get('first_name'), "last_name": request.POST.get('last_name')}
        if not models.User.objects.filter(email=request.POST.get('email')):
            user = models.User.objects.create_user(email=request.POST.get('email'),
                                                   password=request.POST.get('password'),
                                                   **data)
            context["user"] = user
            current_site = get_current_site(request)
            site_name = current_site.name
            domain = current_site.domain
            use_https = self.request.is_secure()
            context = {
                'email': user.email,
                'domain': domain,
                'site_name': site_name,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'user': user,
                'token': default_token_generator.make_token(user),
                'protocol': 'https' if use_https else 'http',

            }
            html_email_template_name = None
            send_mail("Account Activation", self.email_template_name, context, settings.EMAIL_HOST_USER,
                      user.email, html_email_template_name=html_email_template_name,
                      )
        else:
            context["error"] = {"email": "Email Should be unique"}
        return render(request, self.template_name, context=context)


class LoginView(View):
    template_name = 'login.html'
    error_messages = None
    success_url = '/'

    def get(self, request):
        return render(request, self.template_name)

    def post(self, request, **kwargs):
        email = request.POST.get('email')
        password = request.POST.get('password')
        if email and password:
            user = authenticate(self.request, email=email, password=password)
            if user is None:
                self.error_messages = {
                    'invalid_login': _(
                        "Please enter a correct email and password. Note that both "
                        "fields may be case-sensitive."
                    ),
                    'inactive': _("This account is inactive."),
                }
                return render(request, self.template_name, context=self.error_messages)
            else:
                if not user.is_active:
                    self.error_messages = {
                        "invalid_login": "User Is Not Activated"
                    }
                    return render(request, self.template_name, context=self.error_messages)
            login(self.request, user)
            return HttpResponseRedirect(self.success_url)
        return render(request, self.template_name)


class ProfileView(LoginRequiredMixin, TemplateView):
    login_url = '/login'
    template_name = 'profile.html'


class EmailActivationConform(View):
    def get(self, request, **kwargs):
        user = self.get_user(kwargs['uidb64'])
        if user is not None:
            token = kwargs['token']
            if default_token_generator.check_token(user, token):
                user.is_active = True
                user.save()
                return HttpResponseRedirect('/login')
        return HttpResponse("Invalid Token")

    def get_user(self, uidb64):
        try:
            # urlsafe_base64_decode() decodes to bytestring
            uid = urlsafe_base64_decode(uidb64).decode()
            user = models.User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError):
            user = None
        return user
