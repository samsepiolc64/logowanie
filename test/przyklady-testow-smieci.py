

"""


import requests

url = "http://127.0.0.1:5000/user"

payload = "{\"email\":\"ktosik@wp.pl\", \"password\":\"123456\"}"
headers = {
  'Content-Type': 'application/json',
  'x-access-token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwdWJsaWNfaWQiOiIxNzZmYWRiZS0zZDE0LTQ2OTgtYWQ1My0zYjE5ZDAwODNkMTQiLCJleHAiOjE1ODE4NjYyMTZ9.qSRGBzLzR8zMAWoAozfpxo3dJ_YEzfkl9fmYB6GWu7o',
  'Authorization': 'Basic YWRtaW5AYWRtaW4ucGw6MTIzNDU='
}

response = requests.request("GET", url, headers=headers, data = payload)

print(response.text.encode('utf8'))

------------------

def test_post_headers_body_json():
    url = 'http://127.0.0.1:5000/login'

    # Additional headers.
    headers = {'Content-Type': 'application/json'}

    # Body
    #payload = {"email":"admin@admin.pl", "password":"12345"}
    payload = {}

    # convert dict to json by json.dumps() for body data.
    resp = requests.post(url, data=json.dumps(payload, indent=4))

    # Validate response headers and body contents, e.g. status code.
    assert resp.status_code == 405
    #resp_body = resp.json()
    #assert resp_body['url'] == url

    # print response full body as text
    print(resp.text)

----------------------
"""