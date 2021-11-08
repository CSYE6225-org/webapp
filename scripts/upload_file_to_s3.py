import boto3
import sys

def main():
    bucket_name=sys.argv[1]
    aws_key=sys.argv[2]
    aws_access_key=sys.argv[3]
    aws_access_secret=sys.argv[4]
    local_path=sys.argv[5]

    #bucket_name="codedeploy.maneesh"
    #aws_key="weabapp.zip"
    #aws_access_key="AKIA4FDOUDW65OSZKSOE"
    #aws_access_secret="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"
    #local_path="weabapp.zip"

    session = boto3.Session(
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_access_secret,
    )
    client = session.client('s3')

    response = client.upload_file(
        Filename=local_path,
        Bucket=bucket_name,
        Key=aws_key
    )
    print ('Done uploading')


main()