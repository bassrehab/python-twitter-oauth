import urllib, urllib2, collections, hmac, binascii, time, random

from hashlib import sha1

from flask import Flask, redirect, request, session, render_template


#Twitter native module was used to ease the post tweet/fetch tweet actions, due to lack of time.
#Can generate a well formed JSON request and read the same, alternatively.
from twitter import *


#Twitter APP Variables
consumer_key = "OUR_CONSUMER_KEY"
consumer_secret = "OUR_CONSUMER_SECRET"


app = Flask(__name__, static_url_path='')

@app.route('/')
def root():
	

	access_token = session.get('access_token')
	if access_token is None:
		return render_template('index.html')
 	
 	access_token = access_token[0]
 
 	return render_template('loggedin.html')

@app.route('/authenticate')
def authenticate(): 
	#Clear the existing session variables.
	session.clear()
	session['oauth_secret'] = ''
	requestParams = {
		"oauth_callback" : "http://127.0.0.1:5000/authorised", "oauth_consumer_key" : consumer_key,
		"oauth_nonce" : str(random.randint(1, 999999999)), "oauth_signature_method" : "HMAC-SHA1", "oauth_timestamp" : int(time.time()),
		"oauth_version" : "1.0"
	}

	receivedSig = signatureRequest(requestParams, "POST", "https://api.twitter.com/oauth/request_token")

	requestParams["oauth_signature"] = receivedSig
	
	request = urllib2.Request("https://api.twitter.com/oauth/request_token", "") 
	request.add_header("Authorization", formulateOauthHeaders(requestParams))

	try:
		httpResponse = urllib2.urlopen(request)
	except urllib2.HTTPError, e: 
		return e.read()

	responseData = fetchParams(httpResponse.read()) 


	session['oauth_token'] = responseData['oauth_token']
	session['oauth_secret'] = responseData['oauth_token_secret']

	return redirect("https://api.twitter.com/oauth/authorize?oauth_token=" + session['oauth_token'])

@app.route('/authorised')
def authorised():

	if request.args.get('oauth_token', '') == session['oauth_token']:
		verifyRequestParams = {
			"oauth_consumer_key" : consumer_key, "oauth_nonce" : str(random.randint(1, 999999999)), "oauth_signature_method" : "HMAC-SHA1", "oauth_timestamp" : int(time.time()), "oauth_version" : "1.0",
			"oauth_token" : session['oauth_token']
		}

		signVerification = signatureRequest(verifyRequestParams, "POST", "https://api.twitter.com/oauth/access_token")

		verifyRequestParams["oauth_signature"] = signVerification

		verifyRequest = urllib2.Request("https://api.twitter.com/oauth/access_token", "oauth_verifier=" + request.args.get('oauth_verifier'))
		verifyRequest.add_header("Authorization", formulateOauthHeaders(verifyRequestParams))

		try:
			httpResponse = urllib2.urlopen(verifyRequest) 
		except urllib2.HTTPError, e:
			return e.read()

		responseData = fetchParams(httpResponse.read()) 

		#TODO: Flash some relavant message if user denies request? Currently Sign IN block is shown.
		#if responseData is None:
		#	flash('You denied the request to sign in.')
		#	return redirect(next_url)

		# SAVE some data


		session['oauth_token'] = responseData["oauth_token"]
		session['oauth_token_secret'] = responseData["oauth_token_secret"] 
		session['screen_name'] = responseData["screen_name"]

		twitter = Twitter(
		        auth = OAuth(responseData['oauth_token'], responseData['oauth_token_secret'], consumer_key, consumer_secret))


		session['results']= twitter.statuses.user_timeline(screen_name = session['screen_name'], count= 10)
		session['hasNewTweet'] = 'false'

	
	return render_template('loggedin.html')





@app.route('/tweets/', methods=['POST'])
def tweets():
	new_status = request.form['yourstatus']
	f_outh_token = request.form['o_t']
	f_outh_token_secret = request.form['o_t_s']
	f_screen_name = request.form['screen_name']

	print("Token:"+f_outh_token+"  Message:"+ new_status)


	# Let's wrap our request in a try block, to handle 403/401 errors, eg. duplicate tweets that twitter disallows.
	# TODO: Handle individual error types and messages accordingly. Currently only generic failure message shown.
	try:
		
		twitter = Twitter(
			auth = OAuth(f_outh_token, f_outh_token_secret, consumer_key, consumer_secret))

		post_response = twitter.statuses.update(status = new_status)
		session['hasNewTweet'] = 'true'

	except: 
		session['hasErrors'] = 'true'
	

	#Show results in any case.	
	#limit tweet count to 10
	session['results'] = twitter.statuses.user_timeline(screen_name = f_screen_name , count= 10)

	session['screen_name'] = f_screen_name
	session['oauth_token'] = f_outh_token
	session['oauth_token_secret'] = f_outh_token_secret 
	
	return render_template('loggedin.html')




def fetchParams(paramString):

	paramString = paramString.split("&")
	
	pDict = {}

	for parameter in paramString: 
		parameter = parameter.split("=")

		pDict[parameter[0]] = parameter[1] 

	return pDict


def signatureRequest(parameters, method, baseURL):

	baseURL = urllib.quote(baseURL, '')

	p = collections.OrderedDict(sorted(parameters.items(), key=lambda t: t[0]))

	requestString = method + "&" + baseURL + "&" 
	parameterString = ""

	for idx, key in enumerate(p.keys()):
		paramString = key + "=" + urllib.quote(str(p[key]), '') 
		if idx < len(p.keys()) - 1:
			paramString += "&" 

		parameterString += paramString


	result = requestString + urllib.quote(parameterString, '') 

	signingKey = consumer_secret + "&" + session['oauth_secret'] 

	print signingKey

	hashed = hmac.new(signingKey, result, sha1)
	signature = binascii.b2a_base64(hashed.digest())[:-1]

	return signature


def formulateOauthHeaders(oauthParams):

	oauthp = collections.OrderedDict(sorted(oauthParams.items(), key=lambda t: t[0]))
	headerString = "OAuth "

	for idx, key in enumerate(oauthp):
		hString = key + "=\"" + urllib.quote(str(oauthp[key]), '') + "\"" 
		if idx < len(oauthp.keys()) - 1:
			hString += "," 

		headerString += hString
	
	return headerString

if __name__ == '__main__':

	app.secret_key = 'I57DOMCRypy08r3ph2cK3yf0R5267o0P' 
	app.run(host='0.0.0.0', debug=True)

