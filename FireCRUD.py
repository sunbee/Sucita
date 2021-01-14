import requests
import config

def get_authToken():
    """
    Executes a POST request to obatin a bearer token from Firebase auth services.
    Uses the API key for the Firebase project. This key belongs to the project owner.
    It must be kept secure at all times. 

    args: None
    returns: reponse (json) that has the bearer token on success
    usage: bearer_token = get_authToken()['idToken']
    """
    response = None

    # API Essentials
    authAPI_endPoint_signIn = 'https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key='
    API_KEY=config.GoogleServices_API_KEY

    # Collect data for making HTTP request
    URL = authAPI_endPoint_signIn + API_KEY
    print(URL)
    payload = {
        "email": config.email,
        "password": config.password,
        "returnSecureToken": True
    }

    # Make request
    r_auth = requests.post(URL, json=payload)
    response = r_auth.json()

    return response

def firebase_upload_withAuth(auth_token):
    """
    Upload an image to Firebase Storage making an authenticated POST request.
    DEMONSTRATION ONLY, USE NO FURTHER! 
    Structure appropriately for use with FastAPI, then use.

    args: auth_token (string) is the bearer token, send as header for authorization.
    returns: response (json) with the HTTP response
    usage: result = firebase_upload_withAuth(ret_token['idToken'])

    """
    response = None

    file2upload = "/Users/sanjaybhatikar/Downloads/YVCare.png"
    file_binary = open(file2upload, "rb").read()

    # HTTP
    url2file = 'https://firebasestorage.googleapis.com/v0/b/shiva-923e9.appspot.com/o/stash%2FYVCare.png'
    headers = {"Content-Type": "image/png", "Authorization": "Bearer "+auth_token}

    r = requests.post(url2file, data=file_binary, headers=headers)
    response = r.json()
    
    return response