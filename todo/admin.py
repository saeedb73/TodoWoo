from django.contrib import admin
from todo.models import Todo


class TodoAdmin(admin.ModelAdmin):
    readonly_fields = ('datecreated', )

# Register your models here.
admin.site.register(Todo, TodoAdmin)
