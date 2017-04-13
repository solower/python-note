import requests
import json

user_info = {'email': ["L_iquidice@hotmail.com","hotgbox@hotmail.com","abido2farma@gmail.com","ngocnd84@gmail.com"]}
jsondata = json.dumps(user_info)
headers = {"Content-Type":"application/json"}
try:
    r = requests.post("http://127.0.0.1:5000/api-test?offset=2&limit=500", headers = headers, data=jsondata)
except Exception,e:
    print e

print r.text