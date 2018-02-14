const AWS = require("aws-sdk");
const base64url = require("base64url");

class JWTKMS {
    constructor(options) {
		if(!options) {
			options = {
				aws: {
					region: "us-east-1"
				}
			};
		}

        this.kms = new AWS.KMS(options.aws);
    }

    sign(payload, options, key_arn) {
        if(!key_arn) {
            key_arn = options;
            options = {};
        }

        return new Promise((resolve, reject) => {

            var headers = {
                alg: "KMS",
                typ: "JWT"
            };

			if(options.issued_at && options.issued_at instanceof Date )
			{
				payload.iat = Math.ceil( options.issued_at.getTime() / 1000 );
			}
            else if(!payload.iat)
            {
                payload.iat = Math.floor( Date.now() / 1000 );
            }

            if(options.expires && options.expires instanceof Date )
            {
                payload.exp = Math.ceil( options.expires.getTime() / 1000 );
            }

            var token_components = {
                header: base64url( JSON.stringify(headers) ),
                payload: base64url( JSON.stringify(payload) ),
            };

            this.kms.encrypt({
                Plaintext: new Buffer(base64url(token_components.header + "." + token_components.payload), "base64"),
                KeyId: key_arn
            }, function(err, data)
            {
                if(err) return reject(err);

                token_components.signature = data.CiphertextBlob.toString("base64");

                var token = token_components.header + "." + token_components.payload + "." + token_components.signature;

                return resolve(token);
            });
        });
    }

    async verify(token, { 
        arn,
        exipryTimeSeconds = ( 10 * 60 )
    } = {}) {
        const token_components = token.split(".");
        const maxLifetime = Math.abs(exipryTimeSeconds);
        if(token_components.length !== 3) {
            throw new Error("Invalid token");
        }
        
        let header = null;
        let payload = null;
        let encrypted_signature = null;

        try {
            header = JSON.parse(base64url.decode(token_components[0]));
            payload = JSON.parse(base64url.decode(token_components[1]));
            encrypted_signature = token_components[2];
        } catch (err) {
            throw new Error('Invalid token');
        }
        
        const EncryptionContextKey = arn || header.kid;

        if (payload.iat) {
            const issued_at = new Date((payload.iat - maxLifetime) * 1000);

            if (issued_at >= new Date()) {
                throw new Error('Invalid token');
            }
        }

        if (payload.exp) {
            const expires_at = new Date(payload.exp * 1000);

            if( expires_at < new Date() )
            {
                throw new Error('Invalid token');
            }
        }

        try {
            const data = await this.kms.decrypt({
                CiphertextBlob: new Buffer(encrypted_signature, 'base64'),
                EncryptionContext: {
                    EncryptionContextKey
                }
            }).promise();
            const decrypted_signature = base64url.decode(data.Plaintext.toString('base64'));

            if(decrypted_signature == token_components[0] + '.' + token_components[1]) {
                return payload;    
            }
            
            throw new Error('Signature invalid');
        } catch (e) {
            throw new Error('Signature invalid');
        }
    }
}

module.exports = JWTKMS;