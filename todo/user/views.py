import json
from django.shortcuts import render
from rest_framework import status
from rest_framework.response import Response
from django.views.decorators.csrf import csrf_exempt
from rest_framework.views import APIView
from . import models
from datetime import datetime
import base64

import os
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.conf import settings
import boto3
from django.http import Http404

import bcrypt
import logging
import django_statsd
import time
import secrets

logger = logging.getLogger(__name__)

# Create your views here.


class Health(APIView):
    @csrf_exempt
    def get(self, request):
        return Response(data={},status=status.HTTP_200_OK)


class Register(APIView):

    @csrf_exempt
    def post(self, request):
        django_statsd.incr('view_post_user_views_Register_hit')
        django_statsd.start('timer_Register_overall')
        

        #TODO Add validation for email addresses
        if 'first_name' not in request.data or 'last_name' not in request.data or 'password' not in request.data or 'username' not in request.data:
            django_statsd.stop('timer_Register_overall')
            return Response(data={"error": "Mandatory fields are missing"}, status=status.HTTP_400_BAD_REQUEST)
        
        data = {
            "fname": request.data["first_name"],
            "lname": request.data["last_name"],
            "password": request.data["password"],
            "username": request.data["username"],
        }



        if not data.get('password'):
            django_statsd.stop('timer_Register_overall')
            return Response(data={"error": "Password cannor be empty"}, status=status.HTTP_400_BAD_REQUEST)
        
        if not data.get('fname'):
            django_statsd.stop('timer_Register_overall')
            return Response(data={"error": "Frist name cannor be empty"}, status=status.HTTP_400_BAD_REQUEST)

        if not data.get('lname'):
            django_statsd.stop('timer_Register_overall')
            return Response(data={"error": "Last name cannor be empty"}, status=status.HTTP_400_BAD_REQUEST)
        
        if not data.get('username'):
            django_statsd.stop('timer_Register_overall')
            return Response(data={"error": "Username cannor be empty"}, status=status.HTTP_400_BAD_REQUEST)

        from django.core.validators import validate_email
        from django.core.exceptions import ValidationError

        try:
            validate_email(data.get('username'))
        except ValidationError as e:
            django_statsd.stop('timer_Register_overall')
            return Response(data={"error": e}, status=status.HTTP_400_BAD_REQUEST)

        #Encrypt password
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(data.get('password'), salt)

        #Check if user already exists
        try:
            django_statsd.start('timer_Register_database_get_timer')
            user_obj = models.User.objects.using('replica').get(username=data.get('username'))
            django_statsd.stop('timer_Register_database_get_timer')
            if user_obj:
                django_statsd.stop('timer_Register_overall')
                return Response(data={"error": "Username already exists"}, status=status.HTTP_400_BAD_REQUEST)
        except models.User.DoesNotExist:
            django_statsd.stop('timer_Register_database_get_timer')
            django_statsd.start('timer_Register_database_create_timer')
            user_obj = models.User.objects.create(username=data.get('username'),
             first_name=data.get('fname'),
              last_name=data.get('lname'),
              password=hashed)
            django_statsd.stop('timer_Register_database_create_timer')

            dynamodbClient = boto3.client(
                'dynamodb',
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID, 
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                region_name=settings.AWS_REGION_NAME)
            
            expiryTimestamp = int(time.time() + 120)
            token = secrets.token_hex(16)
            dynamodbClient.put_item(
                TableName = 'csye6225-dynamo',
                Item = {
                    'id': {
                        'S': user_obj.username
                    },
                    'token': {
                        'S': token
                    },
                    'TimeToExist': {
                        'N': str(expiryTimestamp) 
                    }
                }
            )
            

            client = boto3.client(
                "sns",
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                region_name=settings.AWS_REGION_NAME
            )

            dic = {
                "EmailAddress":user_obj.username,
                "MessageType":"text",
                "AccessToken":token,
            }

                        
            response = client.publish(

                TopicArn="arn:aws:sns:us-east-1:686302940114:EmailNotificationRecipeEndpoint",
                Message=json.dumps(dic),
                
                MessageAttributes={
                'string': {
                    'DataType': 'String',
                    'StringValue': 'String',
                 }
                }
            )
            json_data = {
                        "id": user_obj.id,
                        "first_name": user_obj.first_name,
                        "last_name": user_obj.last_name,
                        "username": user_obj.username,
                        "account_created": user_obj.account_created,
                        "account_updated": user_obj.account_updated,
                        "verified": user_obj.verified
                    }

            
            django_statsd.stop('timer_Register_overall')
            return Response(data={"message":json_data}, status=status.HTTP_201_CREATED)


class GetUser(APIView):
    @csrf_exempt
    def get(self, request):
        """
        API for updating user
        """
        django_statsd.incr('count_get_user_custom')
        django_statsd.start('timer_GetUser_overall')
        #Check the basic auth
        print(request.META.get('HTTP_AUTHORIZATION', " "))

        auth = request.META['HTTP_AUTHORIZATION'].split()
        str = auth[1].encode("utf-8")
        uname, passwd = base64.b64decode(str).decode("utf-8").split(':')

        try:
            django_statsd.start('timer_GetUser_database_gettimer')
            user_obj = models.User.objects.using('replica').get(username=uname)
            django_statsd.stop('timer_GetUser_database_gettimer')

            if user_obj:
                if user_obj.verified == False:
                    django_statsd.stop('timer_GetUser_overall')
                    return Response(data={"error": "User not verified"}, status=status.HTTP_403_FORBIDDEN)
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
                        "account_updated": user_obj.account_updated,
                        "verified": user_obj.verified,
                        "verified_on": user_obj.verified_on
                    }
                    django_statsd.stop('timer_GetUser_overall')
                    return Response(data=json_data, status=status.HTTP_200_OK)
                else:
                    django_statsd.stop('timer_GetUser_overall')
                    return Response(data={"error": "Password not authenticated"}, status=status.HTTP_403_FORBIDDEN)
        except models.User.DoesNotExist:
            
            django_statsd.stop('timer_GetUser_database_gettimer')
            django_statsd.stop('timer_GetUser_overall')
            return Response(data={"error": "Username does not exist"}, status=status.HTTP_400_BAD_REQUEST)
        
    @csrf_exempt
    def put(self, request):
        """
        Edit
        """
        django_statsd.incr('count_put_user_custom')
        #Check the basic auth
        print(request.META.get('HTTP_AUTHORIZATION', " "))

        auth = request.META['HTTP_AUTHORIZATION'].split()
        str = auth[1].encode("utf-8")
        uname, passwd = base64.b64decode(str).decode("utf-8").split(':')

        try:
            user_obj = models.User.objects.get(username=uname)
            if user_obj:
                if user_obj.verified == False:
                    return Response(data={"error": "User not verified"}, status=status.HTTP_403_FORBIDDEN)
                #Vallidate Password
                password = user_obj.password
                # import pdb
                # pdb.set_trace()
                try:
                    if bcrypt.checkpw(passwd, password):

                        keys = request.data.keys()
                        allowed_keys = ['password', 'first_name', 'last_name']
                        print(keys)

                        if len(set(keys).intersection(set(allowed_keys))) > 0:
                            if request.data.get('password'):
                                salt = bcrypt.gensalt()
                                hashed = bcrypt.hashpw(request.data.get('password'), salt)
                                user_obj.password = hashed
                            if request.data.get('first_name'):
                                user_obj.first_name = request.data.get('first_name')
                            if request.data.get('last_name'):
                                user_obj.last_name = request.data.get('last_name')
                            user_obj.account_updated = datetime.now()
                            django_statsd.start('timer_GetUser_database_savetimer')
                            user_obj.save()
                            django_statsd.stop('timer_GetUser_database_savetimer')
                        else:
                            return Response(data={"error": "Cannot modify values mentioned"}, status=status.HTTP_400_BAD_REQUEST)

                        return Response(status=status.HTTP_204_NO_CONTENT)
                    else:
                        return Response(data={"error": "Password not authenticated"}, status=status.HTTP_400_BAD_REQUEST)
                except:
                    return Response(data={"error": "Password not authenticated"}, status=status.HTTP_403_FORBIDDEN)
        except models.User.DoesNotExist:
            return Response(data={"error": "Username does not exist"}, status=status.HTTP_400_BAD_REQUEST)


class GetProfilePic(APIView):
    """
    API for getting and setting profile pic
    """

    @csrf_exempt
    def get(self, request):
        django_statsd.incr('count_get_picture_custom')
        auth = request.META['HTTP_AUTHORIZATION'].split()
        str = auth[1].encode("utf-8")
        uname, passwd = base64.b64decode(str).decode("utf-8").split(':')

        try:
            user_obj = models.User.objects.using('replica').get(username=uname)
            if user_obj.verified == False:
                return Response(data={"error": "User not verified"}, status=status.HTTP_403_FORBIDDEN)
            imag = models.Image.objects.using('replica').filter(user_id=user_obj).order_by('-upload_date')
            if imag:
                jsob = {
                        "id": imag[0].id,
                        "file_name": imag[0].filename,
                        "url": imag[0].url,
                        "upload_date": imag[0].upload_date,
                        "user_id": imag[0].user_id.id

                }
                return Response(data=jsob, status=status.HTTP_200_OK)
            else:
                raise Http404
        except models.User.DoesNotExist:
            raise Http404


    @csrf_exempt
    def delete(self, request):
        django_statsd.incr('count_delete_picture_custom')
        auth = request.META['HTTP_AUTHORIZATION'].split()
        str = auth[1].encode("utf-8")
        uname, passwd = base64.b64decode(str).decode("utf-8").split(':')

        try:
            user_obj = models.User.objects.using('replica').get(username=uname)
            if user_obj.verified == False:
                return Response(data={"error": "User not verified"}, status=status.HTTP_403_FORBIDDEN)
            imag = models.Image.objects.filter(user_id=user_obj).order_by('-upload_date')
            s3 = boto3.client('s3')
            django_statsd.start('timer_DeletePic_s3_deletetimer')
            s3.delete_object(Bucket=settings.S3_BUCKET_NAME, Key=imag[0].url)
            django_statsd.stop('timer_DeletePic_s3_deletetimer')
            imag.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)

        except models.User.DoesNotExist:
            raise Http404

    @csrf_exempt
    def post(self, request):
        """
        Post API for updating and setting profile pic
        """
        django_statsd.incr('count_upload_picture_custom')
        auth = request.META['HTTP_AUTHORIZATION'].split()
        str = auth[1].encode("utf-8")
        uname, passwd = base64.b64decode(str).decode("utf-8").split(':')

        try:
            user_obj = models.User.objects.using('replica').get(username=uname)
            if user_obj:
                if user_obj.verified == False:
                    return Response(data={"error": "User not verified"}, status=status.HTTP_403_FORBIDDEN)
                #Vallidate Password
                password = user_obj.password
                # import pdb
                # pdb.set_trace()
                try:
                    if bcrypt.checkpw(passwd, password):
                        data = request.FILES['image'] # or self.files['image'] in your form
                        fp = user_obj.id.urn[9:] + '/' + data.name
                        path = default_storage.save(fp, ContentFile(data.read()))
                        tmp_file = os.path.join(settings.MEDIA_ROOT, path)
                        s3 = boto3.client('s3')
                        imag = models.Image.objects.using('replica').filter(user_id=user_obj).order_by('-upload_date')
                        if imag:
                            for i in imag:
                                s3.delete_object(Bucket=settings.S3_BUCKET_NAME, Key=i.url)
                        obj_name = user_obj.id.urn[9:] + '/' + data.name
                        django_statsd.start('timer_UploadPic_s3_uploadtimer')
                        s3.upload_file(tmp_file, settings.S3_BUCKET_NAME, obj_name)
                        django_statsd.stop('timer_UploadPic_s3_uploadtimer')
                        created_img = models.Image.objects.create(user_id=user_obj, filename=data.name, url=fp)
                        json_data = {
                            "id": created_img.id,
                            "file_name": created_img.filename,
                            "url": settings.S3_BUCKET_NAME + '/' + created_img.url,
                            "upload_date": created_img.upload_date,
                            "user_id": created_img.user_id.id,
                        }
                        return Response(data=json_data, status=status.HTTP_200_OK)
                    else:
                        return Response(data={"error": "Password not authenticated"}, status=status.HTTP_400_BAD_REQUEST)
                except:
                    import traceback
                    traceback.print_exc()
                    return Response(data={"error": "Password not authenticated"}, status=status.HTTP_403_FORBIDDEN)
        except models.User.DoesNotExist:
            raise Http404


class VerifyUser(APIView):
    @csrf_exempt
    def get(self, request):
        """
        API for validating user
        """
        if 'token' not in request.GET and 'email' not in request.GET:
            return Response(data={"error": "Mandatory fields are missing"}, status=status.HTTP_400_BAD_REQUEST)
        
        token = request.GET.get('token')
        email = request.GET.get('email')
        
        epochTimeNow = int(time.time())
        dynamodbClient = boto3.client(
                'dynamodb',
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID, 
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                region_name=settings.AWS_REGION_NAME)
        try:
            res = dynamodbClient.query(
                TableName = 'csye6225-dynamo',
                KeyConditionExpression = '#id = :id',
                FilterExpression = '#t > :TimeToExist',
                ExpressionAttributeNames = {
                    '#t': 'TimeToExist',
                    '#id': 'id'
                },
                ExpressionAttributeValues = {
                    ':TimeToExist': {
                        'N': str(epochTimeNow),
                    },
                    ':id': {
                        'S': email
                    },
                }
            )
        except Exception as e:
            print('Exception: ', e)

        if res['Count'] >= 1:
            if res['Items'][0]['token']['S'] == token:
                try:
                    user_obj = models.User.objects.get(username=email)
                    user_obj.verified = True
                    user_obj.verified_on = datetime.now()
                    user_obj.save()
                    return Response(data={'message':"Verifed"}, status=status.HTTP_200_OK)
                except models.User.DoesNotExist:
                    return Response(data={"error": "User does not exist"}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(data={"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)
                


