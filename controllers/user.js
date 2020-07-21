/*==========================
 * User management
 *
 * @description: Manage user session logged in the admin/manager interface.
 * @author: Government of Canada; @duboisp;
 * @version: 1.0
 *
 ===========================*/
 
/*
 * Integration with the passport middleware
 *
 * - https://github.com/ServiceCanada/io.canada.ca/blob/283a7dad2d03564443205f056401dda149911e22/manager/config/passport.js
 */

const passport = require('passport');
const { Strategy: LocalStrategy } = require('passport-local');

const dbConn = module.parent.exports.dbConn;
const ObjectId = require('mongodb').ObjectId;
const _sessionMemTTL = process.env.sessionMemTTL || 30000;


const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const userNameSecretKeyCollection = module.parent.exports.userNameSecretKeyCollection;

const userNamePasswordCollection = module.parent.exports.userNamePasswordCollection;

let keyMap = new Map()
const NO_USER = "noUser";


let memoryUserSession = {}; // Schema: "userId": { {user config} + ttl } 


// Serialization of the user information
passport.serializeUser( ( user, done ) => {
	
	// Save in memory
	memoryUserSession[ user._id ] = user;
	memoryUserSession.ttl = Date.now();
	
	// Only save the user ID inside the session
	done( null, user._id );
});

passport.deserializeUser( ( id, done ) => {
	
	// Query local caching, if not expired
	let user = memoryUserSession[ id ];
	if ( user && ( user.ttl + _sessionMemTTL ) > Date.now() ) {
		return done( null, user );
	}
	
	// Query MongoDB
	dbConn.collection( "users" ).findOne( 
		{
			_id: ObjectId( id )
		},
		{
			projection: {
				_id: 1,
				email: 1,
				accessToTopicId: 1
			}
		}
	).then( ( rDoc ) => {
		
		// Save in memory
		memoryUserSession[ rDoc._id ] = rDoc;
		memoryUserSession.ttl = Date.now();
		
		return done( null, rDoc );
	} );
});



/**
 * Sign in using Email and Password.
 */
passport.use(new LocalStrategy({ usernameField: 'username' }, (email, password, done) => {

	// Query MongoDb to get the User info.
	dbConn.collection( "users" ).findOne( {
			name: email,
			pass: password
		},
		{
			projection: {
				_id: 1,
				email: 1,
				accessToTopicId: 1
			}
		} ).then( ( rDoc ) => {
			
			if ( !rDoc ) {
				return done(null, false, { msg: 'Invalid email or password.' } )
			}
			
			return done( null, rDoc );
			
		} );
}));

/**
 * Login Required middleware.
 */
exports.isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/api/v1/mailing/login');
};


exports.getSecretKey = ( req, res, next ) => {
	
	const secretkey =  crypto.randomBytes(64).toString('base64').replace(/\//g,'_').replace(/\+/g,'-');
	console.log(secretkey);
	// first loading to get secret key, there is no way to get to know the user info
	keyMap.set(NO_USER, secretkey);

	
	userNameSecretKeyCollection.replaceOne( 
		{ username: NO_USER },
		{ username: NO_USER, secretkey: secretkey },
		{ upsert : true}
	).then( () => {
		console.log("1 document inserted on api /test/getSecretKey ");
	}).catch( ( e ) => { 
		console.log( "err while generate secretKey on api /test/getSecretKey" );
		console.log( e );
	});

	res.json({ secretkey: secretkey })
};


// Get all the username Password 
exports.getAllUserNamePassword = ( req, res, next ) => {
	
	userNamePasswordCollection.find({}).toArray(function(err, result) {
		if (err) throw err;
		console.log(result);
		res.sendStatus(200);
	  });
};

// Register
exports.register = ( req, res, next ) => {
	
	
	var { username,  password } = req.body;
	console.log(username + " as username and password " + password);
	let errors = [];

	userNamePasswordCollection.findOne({ username: username }).then(user => {
		if (user) {
		  errors.push({ msg: 'UserName already exists' });
		  console.log("UserName already exists");
		  res.status(200).send("UserName already exists");
		} else {
		  bcrypt.genSalt(10, (err, salt) => {
			bcrypt.hash(password, salt, (err, hash) => {
			  if (err) throw err;
			  password = hash;
			  userNamePasswordCollection.insertOne({username: username, password: password})
			   .then(user => {
				console.log("You are now registered and can log in");
				//res.redirect('/users/login');
				res.sendStatus(200);
			   })
			  .catch(err => {
				  console.log(err);
				  res.sendStatus(500);
			});
			});
		  });
		}
	  });
};

// Generate the key and persist in hashmap
exports.login = ( req, res, next ) => {
	
	
	// Authenticate User
	//res.status(500).send('The email is not registered');
	//console.log( req.headers );
	//console.log( req.body );

	const username = req.body.username;
	const password = req.body.password;
	console.log("username is " + username + " and password is " + password);
	var secretkey;

	// Match user
	userNamePasswordCollection.findOne({
		username: username
		  }).then(user => {
		if (!user) {
			console.log("That email is not registered");
			res.status(500).send('The email is not registered');
		 }  else {
		// Match password
		bcrypt.compare(password, user.password, (err, isMatch) => {
			if (err) throw err;
				if (isMatch) {
				  console.log("Password is matched and user can login");
				  secretkey =  crypto.randomBytes(64).toString('base64').replace(/\//g,'_').replace(/\+/g,'-');
				  console.log(secretkey);
				  keyMap.set(username, secretkey);
			  
				  userNameSecretKeyCollection.replaceOne( 
					  { username: username },
					  { username: username, secretkey: secretkey },
					  { upsert: true }
				  ).then( () => {
					  console.log("1 document inserted on api /test/login");
					  res.json({ secretkey: secretkey });
				  }).catch( ( e ) => { 
					  console.log( "err while generate secretKey on api /test/login" );
					  console.log( e );
				  });
				} else {
				  console.log("Password incorrect");
				}
			  });
		 }
		});
};

// List mailing for the user
exports.getMailingByTopicId = ( req, res, next ) => {
	
	const user = req.user;
	res.json( {
				id: "uid-33",
				created: "2020-06-16",
				updated: "2020-06-16",
				title: "Mailing Title",
				user
			} );
};




/*
 * End points
 *
 * - https://github.com/ServiceCanada/io.canada.ca/blob/master/manager/controllers/user.js
 */



  
/**
 * GET /logout
 * Log out.
 */
exports.logout = (req, res) => {

	// Remove the user from the server cache
	const userId = (req.user ? req.user[ "_id" ] : false );
	memoryUserSession[ userId ] && delete memoryUserSession[ userId ];
	
	// logout
	req.logout();
	req.session.destroy((err) => {
		if ( err ) {
			console.log('Error : Failed to destroy the session during logout.', err);
		}
		req.user = null;
		res.redirect('/api/v1/mailing/login');
	});
};


// Authenticate the JWT and verify that if it is tampered or not
// FORMATE OF TOKEN
// Authorization : Bearer <accessToken>
// Verify Token
exports.verifyToken = (req, res, next) => {
	// check if the secretKey is generated by server
	// check if the request include jws in http header authroization
	const authHeader = req.headers['authorization']
	const token = authHeader && authHeader.split(' ')[1]
	if (token == null) return res.sendStatus(401)
	console.log("incoming token payload : " + token);

	let secretKey ='';
	if (req.body.secretKey){
		secretKey = req.body.secretKey;
		jwt.verify(token, secretKey, (err, decoded) => {
			console.log(err)
			if (err) return res.sendStatus(403)
			console.log("decoded payload : " + decoded.name);
			console.log("decoded payload : " + decoded.sub);
			console.log("decoded payload : " + decoded.iat);
			req.user = decoded
			next()
		  })
	} else {
		let payload = token.split('.')[1];
		let buff = new Buffer(payload, 'base64');
		let payLoadJson = JSON.parse(buff.toString('ascii'));
		let userNameFromPayload = payLoadJson.name;
		secretKey = keyMap.get(userNameFromPayload);

	  
		userNameSecretKeyCollection.find({}).toArray(function(err, result) {
			if (err) throw err;
			console.log(result);
		  });

		userNameSecretKeyCollection.findOne(
			{ userName: userNameFromPayload	}
		).then((documentRecord) => {
			console.log("userName in payload in verify : " + documentRecord.userName);
			console.log("secretKey in mongoDb : " + documentRecord.secretKey);
			jwt.verify(token, documentRecord.secretKey, (err, decoded) => {
				console.log(err)
				if (err) return res.sendStatus(403)
				console.log("decoded payload : " + decoded.name);
				console.log("decoded payload : " + decoded.sub);
				console.log("decoded payload : " + decoded.iat);
				req.user = decoded
				next()
			  })
		}).catch( (e) => {
			console.log( "look up document by useName in verify" );
			console.log( e );
		});
	}

  }
