/*
 * User login initial page
 */
const dbConn = module.parent.exports.dbConn;
const fsPromises = require('fs').promises;
const mustache = require('mustache');
const crypto = require('crypto');
const NO_USER = "noUser";

exports.v_mailingLogin = async ( req, res, next ) => {

	
	let secretkey =  crypto.randomBytes(64).toString('base64').replace(/\//g,'_').replace(/\+/g,'-');
	console.log("secretKey is created " + secretkey);

	dbConn.collection( "usersecretkeys" ).replaceOne( 
		{ name: NO_USER },
		{ name: NO_USER, secretkey: secretkey },
		{ upsert : true}
	).then( () => {
		console.log("1 document inserted on api /api/v1/mailing/login ");
	}).catch( ( e ) => { 
		console.log( "err while generate secretKey on api /test/getSecretKey" );
		console.log( e );
	});

	
	var mailingLoginTemplate = await fsPromises.readFile('views/mailingLogin.mustache', 'UTF-8');

	mailingLoginTemplate = mustache.render(mailingLoginTemplate,
		{
			secretkey: secretkey
				
		}
);
	
    res.status( 200 ).send(mailingLoginTemplate);
}
