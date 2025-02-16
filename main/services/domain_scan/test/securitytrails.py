import requests

url = "https://api.securitytrails.com/v1/domain/oracle.com"

headers = {
    "accept": "application/json",
    "APIKEY": "DsegkFLNSr557inExL6iHe0VxRgE4Ixr"
}

response = requests.get(url, headers=headers)

print(response.text)