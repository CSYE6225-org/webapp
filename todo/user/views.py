from django.shortcuts import render
from rest_framework import status
from rest_framework.response import Response
from django.views.decorators.csrf import csrf_exempt
from rest_framework.views import APIView
from . import models
import base64

import bcrypt

# Create your views here.

class Register(APIView):

    @csrf_exempt
    def post(self, request):
        #TODO Add validation for email addresses
        if 'first_name' not in request.data or 'last_name' not in request.data or 'password' not in request.data or 'username' not in request.data:
            return Response(data={"error": "Mandatory fields are missing"}, status=status.HTTP_400_BAD_REQUEST)
        
        data = {
            "fname": request.data["first_name"],
            "lname": request.data["last_name"],
            "password": request.data["password"],
            "username": request.data["username"],
        }

        if not data.get('password'):
            return Response(data={"error": "Password cannor be empty"}, status=status.HTTP_400_BAD_REQUEST)
        
        if not data.get('fname'):
            return Response(data={"error": "Frist name cannor be empty"}, status=status.HTTP_400_BAD_REQUEST)

        if not data.get('lname'):
            return Response(data={"error": "Last name cannor be empty"}, status=status.HTTP_400_BAD_REQUEST)
        
        if not data.get('username'):
            return Response(data={"error": "Username cannor be empty"}, status=status.HTTP_400_BAD_REQUEST)

        #Encrypt password
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(data.get('password'), salt)

        #Check if user already exists
        try:
            user_obj = models.User.objects.get(username=data.get('username'))
            if user_obj:
                return Response(data={"error": "Username already exists"}, status=status.HTTP_400_BAD_REQUEST)
        except models.User.DoesNotExist:
            models.User.objects.create(username=data.get('username'),
             first_name=data.get('fname'),
              last_name=data.get('lname'),
              password=hashed)
            return Response(data={"message": "User created successfully"}, status=status.HTTP_200_OK)

    @csrf_exempt
    def get(self, request):
        """
        API for updating user
        """

        #Check the basic auth
        print(request.META.get('HTTP_AUTHORIZATION', " "))

        auth = request.META['HTTP_AUTHORIZATION'].split()
        str = auth[1].encode("utf-8")
        uname, passwd = base64.b64decode(str).decode("utf-8").split(':')

        try:
            user_obj = models.User.objects.get(username=uname)
            if user_obj:
                #Vallidate Password
                password = user_obj.password
                # import pdb
                # pdb.set_trace()
                if bcrypt.checkpw(passwd, password):
                    #User Authenticated
                    json_data = {
                        "id": user_obj.id,
                        "first_name": user_obj.first_name,
                        "last_name": user_obj.last_name,
                        "username": user_obj.username,
                        "account_created": user_obj.account_created,
                        "account_updated": user_obj.account_updated
                    }

                    return Response(data=json_data, status=status.HTTP_200_OK)
                else:
                    return Response(data={"error": "Password not authenticated"}, status=status.HTTP_400_BAD_REQUEST)
        except models.User.DoesNotExist:
            return Response(data={"error": "Username does not exist"}, status=status.HTTP_400_BAD_REQUEST)

        return Response(data={"message": "User created successfully"}, status=status.HTTP_200_OK)

    @csrf_exempt
    def put(self, request):
        """
        Edit
        """
        #Check the basic auth
        print(request.META.get('HTTP_AUTHORIZATION', " "))

        auth = request.META['HTTP_AUTHORIZATION'].split()
        str = auth[1].encode("utf-8")
        uname, passwd = base64.b64decode(str).decode("utf-8").split(':')

        try:
            user_obj = models.User.objects.get(username=uname)
            if user_obj:
                #Vallidate Password
                password = user_obj.password
                # import pdb
                # pdb.set_trace()
                if bcrypt.checkpw(passwd, password):

                    if request.data.get('password'):
                        user_obj.password = request.data.get('password')
                    if request.data.get('first_name'):
                        user_obj.first_name = request.data.get('first_name')
                    if request.data.get('last_name'):
                        user_obj.first_name = request.data.get('last_name')
                    user_obj.save()

                    return Response(data={"msg":"User updated"}, status=status.HTTP_200_OK)
                else:
                    return Response(data={"error": "Password not authenticated"}, status=status.HTTP_400_BAD_REQUEST)
        except models.User.DoesNotExist:
            return Response(data={"error": "Username does not exist"}, status=status.HTTP_400_BAD_REQUEST)











       
        
        



        







