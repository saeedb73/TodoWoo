from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.db import IntegrityError
from django.contrib.auth import login, logout, authenticate
from todo.models import Todo
from todo.forms import TodoForm
from django.utils import timezone


# Create your views here.
def home(request):
    return render(request, 'todo/home.html')


def signupuser(request):
    if request.method == 'GET':
        return render(request, 'todo/signupuser.html', {'form': UserCreationForm()})

    elif request.method == 'POST':
        if request.POST['password1'] == request.POST['password2']:
            try:
                user = User.objects.create_user(request.POST['username'], password=request.POST['password1'])
                user.save()
                login(request, user)
                return redirect('currenttodos')
            except IntegrityError:
                return render(request, 'todo/signupuser.html', {'form':UserCreationForm, 'error': "This username is taken. Please choose another one."})
        else:
            return render(request, 'todo/signupuser.html', {'form': UserCreationForm(), 'error': "The passwords didn't match"})


def loginuser(request):
    if request.method == 'GET':
        return render(request, 'todo/loginuser.html', {'form': AuthenticationForm()})

    elif request.method == 'POST':
        user = authenticate(request, username=request.POST['username'], password=request.POST['password'])
        if user is None:
            return render(request, 'todo/loginuser.html', {'form': AuthenticationForm(), 'error': "Username and password didn't match"})
        else:
            login(request, user)
            return redirect('currenttodos')    


def logoutuser(request):
    if request.method == 'POST':
        logout(request)
        return redirect('home')


def createtodo(request):
    if request.method == 'GET':
        return render(request, 'todo/createtodo.html', {'form': TodoForm()})
    elif request.method == 'POST':
        try:
            form = TodoForm(request.POST)
            newtodo = form.save(commit=False)
            newtodo.user = request.user
            newtodo.save()
            return redirect('currenttodos')
        except ValueError:
            return render(request, 'todo/createtodo.html', {'form': TodoForm(), 'error': 'Bad data passed in. Try again'})
        

def currenttodos(request):
    if request.user.is_superuser:
        todos = Todo.objects.filter(datecompleted__isnull=True)
    else:
        todos = Todo.objects.filter(user=request.user, datecompleted__isnull=True)
    return render(request, 'todo/currenttodos.html', {'todos': todos})


def viewtodo(request, todo_pk):
    if request.user.is_superuser:
        todo_object = get_object_or_404(Todo, pk=todo_pk)
    else:
        todo_object = get_object_or_404(Todo, pk=todo_pk, user=request.user)
    if request.method == 'GET':
        form = TodoForm(instance=todo_object)
        return render(request, 'todo/viewtodo.html', {'todo': todo_object, 'form': form})
    elif request.method == 'POST':
        try:
            form = TodoForm(request.POST, instance=todo_object)
            form.save()
            return redirect('currenttodos')
        except ValueError:
            return render(request, 'todo/viewtodo.html', {'todo': todo_object, 'form': form, 'error': 'Bad info.'})


def completetodo(request, todo_pk):
    if request.user.is_superuser:
        todo_object = get_object_or_404(Todo, pk=todo_pk)
    else:
        todo_object = get_object_or_404(Todo, pk=todo_pk, user=request.user)
    if request.method == 'POST':
        todo_object.datecompleted = timezone.now()
        todo_object.save()
        return redirect('currenttodos')


def deletetodo(request, todo_pk):
    if request.user.is_superuser:
        todo_object = get_object_or_404(Todo, pk=todo_pk)
    else:
        todo_object = get_object_or_404(Todo, pk=todo_pk, user=request.user)
    if request.method == 'POST':
        todo_object.delete()
        return redirect('currenttodos')