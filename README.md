# FULL DEPLOYMENT OF PYTHON FLASK APPLICATION AND DATABASE TO AMAZON WEB SERVICES

📘 Full Deployment Documentation: Python Web App to AWS Elastic Beanstalk with RDS + Jenkins CI/CD (Free Tier, No Custom Domain)
________________________________________
🧰 Prerequisites
Before beginning the deployment, ensure the following requirements are met:
•	✅ AWS account with access to free-tier resources
•	✅ A Python web application (e.g., Flask or Django)
•	✅ Elastic Beanstalk CLI installed locally
•	✅ An RDS database (MySQL or PostgreSQL)
•	✅ Jenkins installed either locally or on a t2.micro EC2 instance
•	✅ Your code hosted in a Git repository (e.g., GitHub or GitLab)
•	✅ You do not need a custom domain — AWS provides a free public URL
________________________________________
📁 Project Structure
Organize your project directory as follows:
my-app/
│
├── application.py         # Main entry point with WSGI application object
├── requirements.txt       # Python dependencies
├── .ebextensions/         # (optional) Configuration for EB environment
├── Jenkinsfile            # Jenkins CI/CD pipeline definition
├── templates/, static/    # HTML and static files
⚠️ Important: Elastic Beanstalk expects a file named application.py containing a variable called application. If your entry point is app.py, add a wrapper:
from app import app as application
________________________________________
🚀 Step-by-Step: Deploying to AWS Elastic Beanstalk
Understanding EC2 Usage
Elastic Beanstalk automates infrastructure management. It provisions and manages EC2 instances for your application, so you don't need to manually launch an EC2 instance for app hosting.
There are two EC2 roles in this setup:
1.	Elastic Beanstalk EC2 (Automatic)
o	Beanstalk creates and manages an EC2 instance to host your app.
o	You do not manage this instance directly.
2.	Jenkins EC2 (Manual)
o	You launch your own EC2 instance to install and run Jenkins.
o	Jenkins performs automated CI/CD tasks and triggers eb deploy.
________________________________________
Step 1: Install the Elastic Beanstalk CLI
Install the EB CLI (Elastic Beanstalk Command Line Interface):
pip install awsebcli --upgrade --user
export PATH=$HOME/.local/bin:$PATH
Verify installation:
eb --version
Step 2: Initialize the EB Application
Run this in your app directory:
eb init -p python-3.8 my-eb-app
Follow the prompts:
•	Choose a region (e.g., us-east-1)
•	Create or select an Elastic Beanstalk application
•	Skip SSH configuration unless required
Step 3: Create and Deploy the Environment
Launch your application environment:
eb create my-env --instance_type t2.micro
Then deploy your code:
eb deploy
Elastic Beanstalk will provide a public URL, like:
http://my-env.eba-xyz123.us-east-1.elasticbeanstalk.com
No custom domain is needed — this AWS-provided URL is fully functional.
To open your deployed app in the browser:
eb open
Step 4: Set Environment Variables for RDS Access
Once your RDS instance is created, set credentials as environment variables:
eb setenv DB_HOST=mydb.xxxx.rds.amazonaws.com \
           DB_USER=myuser \
           DB_PASS=mypassword \
           DB_NAME=mydbname
Access these variables in your Python app:
import os

host = os.environ['DB_HOST']
user = os.environ['DB_USER']
password = os.environ['DB_PASS']
database = os.environ['DB_NAME']
________________________________________
🧪 Sample Flask Application
application.py
from flask import Flask
import os

app = Flask(__name__)

@app.route('/')
def home():
    return "Hello from AWS Elastic Beanstalk with RDS!"

application = app
requirements.txt
Flask==2.2.5
mysql-connector-python==8.0.33
gunicorn==21.2.0
________________________________________
🛠️ Adding CI/CD with Jenkins
Step 1: Install Jenkins (on EC2 Free Tier)
1.	Launch a t2.micro Ubuntu EC2 instance manually from the AWS EC2 console
2.	Open ports 22 (SSH) and 8080 (Jenkins)
3.	Install Jenkins:
sudo apt update && sudo apt install -y openjdk-11-jdk
wget -q -O - https://pkg.jenkins.io/debian/jenkins.io.key | sudo apt-key add -
echo deb https://pkg.jenkins.io/debian binary | sudo tee /etc/apt/sources.list.d/jenkins.list
sudo apt update && sudo apt install -y jenkins
sudo systemctl start jenkins
sudo systemctl enable jenkins
4.	Access Jenkins via: http://<your-ec2-ip>:8080
Step 2: Jenkins Setup
•	Retrieve admin password:
sudo cat /var/lib/jenkins/secrets/initialAdminPassword
•	Install suggested plugins and create an admin user
•	Install the following plugins:
o	Git
o	Pipeline
o	AWS CLI
o	Credentials Binding
Step 3: Add AWS Credentials
•	Jenkins → Manage Jenkins → Credentials → Add Credentials
•	Type: AWS Credentials
•	ID: aws-eb
•	Add your IAM Access Key and Secret Key
Step 4: Add Jenkinsfile to Your Project
This file defines your Jenkins pipeline:
pipeline {
    agent any

    environment {
        AWS_DEFAULT_REGION = 'us-east-1'
        EB_APP_NAME = 'my-eb-app'
        EB_ENV_NAME = 'my-env'
    }

    stages {
        stage('Checkout') {
            steps {
                git 'https://github.com/your-user/your-repo.git'
            }
        }

        stage('Install Dependencies') {
            steps {
                sh 'pip install -r requirements.txt'
            }
        }

        stage('Deploy to Elastic Beanstalk') {
            steps {
                withCredentials([[$class: 'AmazonWebServicesCredentialsBinding', credentialsId: 'aws-eb']]) {
                    sh '''
                        eb init $EB_APP_NAME --region $AWS_DEFAULT_REGION --platform "Python 3.8" || true
                        eb use $EB_ENV_NAME
                        eb deploy
                    '''
                }
            }
        }
    }
}
Step 5: Create a Jenkins Pipeline Job
•	Go to Jenkins → New Item → Pipeline
•	Select Pipeline script from SCM
•	Set:
o	Git repository URL
o	Branch: main or master
o	Script path: Jenkinsfile
Step 6: Add GitHub Webhook (Optional)
To trigger builds automatically:
•	GitHub → Repo Settings → Webhooks → Add Webhook
•	Payload URL: http://<jenkins-ip>:8080/github-webhook/
•	Content type: application/json
•	Trigger: Push events only
________________________________________
## Stay Within AWS Free Tier
AWS Service	Free Tier Limits	Guidelines
EC2 (Jenkins)	750 hours/month for t2.micro	Use only one instance at a time
Elastic Beanstalk	Uses EC2, S3, CloudWatch (all free-tier eligible)	Automatically uses t2.micro
RDS	750 hours/month for db.t3.micro + 20GB	One database, delete when not in use
S3	5 GB	Don’t store large files/logs
CloudWatch	Basic monitoring is free	Avoid enhanced logging/alarms
________________________________________
## Cleanup Checklist
To avoid unexpected charges:
1.	Terminate EB environment:
eb terminate my-env
2.	Delete RDS instance via AWS Console
3.	Delete Jenkins EC2 instance
4.	Remove any S3 buckets created by Beanstalk
5.	Check Billing Dashboard for unused resources
________________________________________
# Final Summary
•	✅ Python app is structured and ready for production
•	✅ Deployed using Elastic Beanstalk on a managed EC2 instance
•	✅ RDS database created and connected via environment variables
•	✅ Jenkins installed on a separate EC2 instance and integrated with GitHub
•	✅ Jenkins automates app deployment on code push
•	✅ AWS provides a working URL (no domain name required!)
________________________________________
### Need help generating IAM roles, connecting CloudWatch to Jenkins, exporting this doc to GitHub or PDF? Let me know!

