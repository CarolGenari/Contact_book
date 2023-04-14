from django.contrib import auth, messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.validators import validate_email
from django.shortcuts import redirect, render

from .models import FormContato


def login(request):
    if request.method != 'POST':
        return render(request, 'accounts/login.html')

    user = request.POST.get('user')
    password = request.POST.get('password')

    usuario = auth.authenticate(request, username=user, password=password)

    if not user:
        messages.error(request, 'Usuário ou senha inválidos.')
        return render(request, 'accounts/login.html')
    else:
        auth.login(request, usuario)
        messages.success(request, 'Login realizado com sucesso')
        return redirect('dashboard')


def logout(request):
    auth.logout(request)
    return redirect('index')


def register(request):
    if request.method != 'POST':
        return render(request, 'accounts/register.html')

    name = request.POST.get('name')
    last_name = request.POST.get('last_name')
    email = request.POST.get('email')
    user = request.POST.get('user')
    password = request.POST.get('password')
    password2 = request.POST.get('password2')

    if not name or not last_name or not email or not user or not password \
            or not password2:
        messages.error(request, 'Nenhum campo pode estar vazio.')
        return render(request, 'accounts/register.html')

    try:
        validate_email(email)
    except:
        messages.error(request, 'Email inválido')
        return render(request, 'accounts/register.html')

    if len(user) < 6:
        messages.error(request, 'User deve conter 6 caracteres ou mais.')
        return render(request, 'accounts/register.html')

    if len(password) < 6:
        messages.error(request, 'Senha deve conter 6 caracteres ou mais.')
        return render(request, 'accounts/register.html')

    if password != password2:
        messages.error(request, 'Senhas não conferem.')
        return render(request, 'accounts/register.html')

    if User.objects.filter(username=user).exists():
        messages.error(request, 'Usuário já existe.')
        return render(request, 'accounts/register.html')

    if User.objects.filter(email=email).exists():
        messages.error(request, 'Email já existe.')
        return render(request, 'accounts/register.html')

    messages.success(request, 'Registrado com sucesso! Faça login.')

    user = User.objects.create_user(
        username=user, email=email, password=password, first_name=name,
        last_name=last_name
    )
    user.save()

    return redirect('login')


@login_required(redirect_field_name='login')
def dashboard(request):
    if request.method != 'POST':
        form = FormContato()
        return render(request, 'accounts/dashboard.html', {'form': form})

    form = FormContato(request.POST, request.FILES)

    if not form.is_valid():
        messages.error(request, 'Erro ao enviar formulário.')
        form = FormContato(request.POST)
        return render(request, 'accounts/dashboard.html', {'form': form})

    descricao = request.POST.get('descricao')

    if len(descricao) < 5:
        messages.error(
            request, 'Descrição precisa ter mais do que 5 caracteres')
        form = FormContato(request.POST)
        return render(request, 'accounts/dashboard.html', {'form': form})

    form.save()
    messages.success(
        request, f'Contato {request.POST.get("nome")} salvo com sucesso!')
    return redirect('dashboard')
