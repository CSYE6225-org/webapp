from django.shortcuts import render
from django.http import JsonResponse
# Create your views here.
def list_view(request, *args, **kwargs):
    data =  {
        "id" : 1,
        "name" : "Maneesh"
    }
    return JsonResponse(data)

