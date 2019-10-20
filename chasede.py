import json
from base64 import b64decode

import requests
from bs4 import BeautifulSoup as bs
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA


def get_login_session(userid, password):
    login_url = 'https://icampus.skku.edu/xn-sso/customs/pages/logon-url.php'
    cbf_url = 'https://icampus.skku.edu/xn-sso/login.php?auto_login=true&sso_only=true&cvs_lgn=&return_url=https%3A%2F%2Ficampus.skku.edu%2Fxn-sso%2Fgw-cb.php%3Ffrom%3Dweb_redirect%26login_type%3Dstandalone%26return_url%3Dhttps%253A%252F%252Ficampus.skku.edu%252Flogin%252Fcallback'

    session = requests.session()

    params = dict()
    params['login_user_id'] = userid
    params['login_user_password'] = password
    header = {
            'Referer': cbf_url,
            'Sec-Fetch-Mode':'no-cors',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36 OPR/63.0.3368.56786'
        }

    first_page = session.get('https://icampus.skku.edu/login')
    html = first_page.text
    soup = bs(html, 'html.parser')
    token = soup.find('input', {'id': 'loginFormToken'})
    cbftoken = soup.find('input', {'id': 'cbFormToken'})
    params['login_form_token'] = token['value']

    res = session.post(login_url, data = params, headers=header) 

    res.raise_for_status()
    login_response = json.loads(res.text)
    hakbun = login_response[0]['user_no']
    params['login_user_no'] = hakbun
    params['login_form_token'] = cbftoken['value']
    res = session.post('https://icampus.skku.edu/xn-sso/gw-cb.php?from=web_redirect&login_type=standalone&return_url=https%3A%2F%2Ficampus.skku.edu%2Flogin%2Fcallback', allow_redirects=False, data=params, headers={
        'Referer': 'https://icampus.skku.edu/xn-sso/login.php?auto_login=true&sso_only=true&cvs_lgn=&return_url=https%3A%2F%2Ficampus.skku.edu%2Fxn-sso%2Fgw-cb.php%3Ffrom%3Dweb_redirect%26login_type%3Dstandalone%26return_url%3Dhttps%253A%252F%252Ficampus.skku.edu%252Flogin%252Fcallback'
    })

    token1 = res.headers['Location'].split('=')
    res = session.get(res.headers['Location'])
    token1[0] = 'https://canvas.skku.edu/learningx/login?result='
    res = session.get(token1[0] + token1[1])


    soup = bs(res.text, 'html.parser')
    script = soup.find('script', {'type':'text/javascript'})
    a = str(script).split('"')
    publickey = a[3]
    privatekey = a[5]

    privatekey = RSA.import_key(privatekey)
    privatekey = PKCS1_v1_5.new(privatekey)

    decrypt = privatekey.decrypt(b64decode(publickey), 'bolloux').decode('utf-8')
    res = session.post('https://canvas.skku.edu/login/canvas', data={
        'utf8':'✓',
        'redirect_to_ssl': '1',
        'pseudonym_session[unique_id]': hakbun,
        'pseudonym_session[password]': decrypt,
        'pseudonym_session[remember_me]': '0'
    }, headers={
        'Host': 'canvas.skku.edu',
        'Connection': 'keep-alive',
        'Content-Length': '166',
        'Cache-Control': 'max-age=0',
        'Origin': 'https://canvas.skku.edu',
        'Upgrade-Insecure-Requests': '1',
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36 OPR/63.0.3368.56786',
        'Sec-Fetch-Mode': 'nested-navigate',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'Sec-Fetch-Site': 'same-origin',
        'Referer': 'https://canvas.skku.edu/learningx/login?result=RnoVU9XSfQztgWK1vYWuevc14b6UKuaa1y7wUELqfitEzs%2FVLOZtOTK8RDDC3YtVYuU6ijAhEk%2FGXlx96cWNFClxyoGuwVYEJVLie2wXsg7xWbFPQ0BYOpvjrwa%2FMuXGzIdlBd1Hvw50qqItKFjbUBAtJ6D4Nb5UcTkwM2ReDHNI8jXyfg1tD1E2ruq2mGOJBLKDw%2BSDdtWElAK09Cog5lHY6BvWJUDDNtWD6K3pz7o5gZhfio%2FUMpJ4oGc7QBgkPVhfl0j3tbJqJdc7vQlJiAG4uFfyWmp6MdXxpQI6XvXXwmVJL85H2jl8%2FMLSI7Y3',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7'
    })
    res = session.get('https://canvas.skku.edu/?login_success=1')
    return session