from locust import HttpUser, task

class HelloWorldUser(HttpUser):
    @task
    def hello_world(self):
	    self.client.get('/v2/user/self', auth=('jai1@example.com', 'password'))


