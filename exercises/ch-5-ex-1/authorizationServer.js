var express = require("express");
var url = require("url");
var bodyParser = require('body-parser');
var randomstring = require("randomstring");
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var querystring = require('querystring');
var __ = require('underscore');
__.string = require('underscore.string');

var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for the token endpoint)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/authorizationServer');
app.set('json spaces', 4);

// authorization server information
var authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token'
};

// client information
var clients = [

  /*
   * Enter client information here
   */

	{
		"client_id": "oauth-client-1",
		"client_secret": "oauth-client-secret-1",
		"redirect_uris": ["http://localhost:9000/callback"]
	}
];

var codes = {};

var requests = {};

var getClient = function(clientId) {
	return __.find(clients, function(client) { return client.client_id == clientId; });
};

app.get('/', function(req, res) {
	res.render('index', {clients: clients, authServer: authServer});
});

app.get("/authorize", function(req, res){

	const { client_id, redirect_uri } = req.query;
	const client = getClient(client_id);

	if(!client){
		res.render('error', {error: 'Unknown client'});
		return;
	}else if(!__.contains(client.redirect_uris, redirect_uri)){
		res.render('error', {error: 'Invalid redirect URI'});
		return;
	}else{
		const reqid = randomstring.generate(8);
		requests[reqid] = req.query;
		res.render('approve', {client, reqid });
		return;
	}
	
});

app.post('/approve', function(req, res) {

	/*
	 * Process the results of the approval page, authorize the client
	 */
	const reqid = req.body.reqid;
	const query = requests[reqid];
	delete requests[reqid];

	if(!query){
		res.render('error', {error : 'No matching authorization request'});
		return;
	}

	if(req.body.approve){

		if(query.response_type == 'code'){
			const code = randomstring.generate(8);

			codes[code] = { request : query };

			const urlParsed = buildUrl(query.redirect_uri,{
				code,
				state : query.state
			});

			res.redirect(urlParsed);

		}else{

			const urlParsed = buildUrl(query.redirect_uri, {
				error: 'unsupported_response_type'
			});

			res.redirect(urlParsed);
			return;
		}

	}else{
		const urlParsed = buildUrl(query.redirect_uri, {
			error: 'access_denied'
		});
		res.redirect(urlParsed);
		return;
	}

});

app.post("/token", function(req, res){

	/*
	 * Process the request, issue an access token
	 */

	let clientId;
	let clientSecret;

	const auth = req.headers['authorization'];
	if(auth){
		const clientCredentials = decodeClientCredentials(auth);
		clientId = clientCredentials.id;
		clientSecret = clientCredentials.secret;
	}

	if(req.body.client_id){
		if(clientId){
			res.status(401).json({error : 'invalid_client'});
			return;
		}

		clientId = req.body.client_id;
		clientSecret = req.body.client_secret;
	}

	const client = getClient(clientId);
	if (!client) {
		console.log('Unknown client %s', clientId);
		res.status(401).json({error: 'invalid_client'});
		return;
	}

	if (client.client_secret != clientSecret) {
		console.log('Mismatched client secret, expected %s got %s', client.client_secret, clientSecret);
		res.status(401).json({error: 'invalid_client'});
		return;
	}

	if (req.body.grant_type == 'authorization_code') {

		var code = codes[req.body.code];

		if (code) {
			delete codes[req.body.code]; // burn our code, it's been used
			if (code.request.client_id == clientId) {

				var access_token = randomstring.generate();
				nosql.insert({ access_token: access_token, client_id: clientId });


				console.log('Issuing access token %s', access_token);
				console.log('with scope %s', code.scope);

				var token_response = { access_token: access_token, token_type: 'Bearer' };

				res.status(200).json(token_response);
				console.log('Issued tokens for code %s', req.body.code);

				return;
			} else {
				console.log('Client mismatch, expected %s got %s', code.request.client_id, clientId);
				res.status(400).json({error: 'invalid_grant'});
				return;
			}

		} else {
			console.log('Unknown code, %s', req.body.code);
			res.status(400).json({error: 'invalid_grant'});
			return;
		}

	} else {
		console.log('Unknown grant type %s', req.body.grant_type);
		res.status(400).json({error: 'unsupported_grant_type'});
	}


});

var buildUrl = function(base, options, hash) {
	var newUrl = url.parse(base, true);
	delete newUrl.search;
	if (!newUrl.query) {
		newUrl.query = {};
	}
	__.each(options, function(value, key, list) {
		newUrl.query[key] = value;
	});
	if (hash) {
		newUrl.hash = hash;
	}
	
	return url.format(newUrl);
};

var decodeClientCredentials = function(auth) {
	var clientCredentials = Buffer.from(auth.slice('basic '.length), 'base64').toString().split(':');
	var clientId = querystring.unescape(clientCredentials[0]);
	var clientSecret = querystring.unescape(clientCredentials[1]);	
	return { id: clientId, secret: clientSecret };
};

app.use('/', express.static('files/authorizationServer'));

// clear the database
nosql.clear();

var server = app.listen(9001, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('OAuth Authorization Server is listening at http://%s:%s', host, port);
});
 
