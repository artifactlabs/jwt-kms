const assert = require('assert');
const should = require('should');
const should_http = require('should-http');

describe('JWT-KMS', function() {
    var jwtkms = null,
        created_signing_key = null,
        public_key = 'my secret',
        token = null;

    it('should take a test arn in an ENV variable', function() {
        process.env.should.have.property('KEY_ARN');
	});
	
	it('should instantiate an instance with a empty config', function() {
        jwtkms = new (require('../index.js'))();
		should.exist(jwtkms);
    });

    it('should instantiate an instance', function() {
        jwtkms = new (require('../index.js'))({
            aws: {
                region: 'us-east-1'
            }
        });

        should.exist(jwtkms);
    });

    it('should sign a payload', function() {
        return jwtkms.sign({foo: 'bar'}, process.env.KEY_ARN).then(function (new_token) {
            should.exist(new_token);
            token = new_token;
        });
    });

    it('should verify a token', function() {
        return jwtkms.verify(token).then(function(decoded) {
            should.exist(decoded);
            decoded.should.have.property('foo').eql('bar');
            decoded.should.have.property('iat');
            decoded.should.not.have.property('exp');
        });
    });

    it('should sign a payload with expiration date', function () {
        return jwtkms.sign({foo: 'bar'}, {expires: new Date(Date.now() + 10000)}, process.env.KEY_ARN).then(function (new_token) {
            should.exist(new_token);
            token = new_token;
        });
    });

    it('should verify a token with a valid expiration date', function() {
        return jwtkms.verify(token).then(function(decoded) {
            should.exist(decoded);
            decoded.should.have.property('foo').eql('bar');
            decoded.should.have.property('iat');
            decoded.should.have.property('exp');
        });
    });

    it('should sign a payload with expired expiration date', function() {
        return jwtkms.sign({foo: 'bar'}, {expires: new Date(Date.now() - 2000)}, process.env.KEY_ARN).then(function (new_token) {
            should.exist(new_token);
            token = new_token;
        });
    });

    it('should not verify an expired token', function() {
        return jwtkms.verify(token).then(function(decoded) {
            throw new Error('Should not verify this token');
        }).catch(function (err) { should.exist(err); });
    });

    it('should not verify an invalid token', function(done) {
        var token_parts = token.split('.');

        jwtkms.verify(token_parts[0] + '.' + token_parts[1] + '.' + 'AQICAHh7R1QbF3+WxosbJFTfuTKfFZH+61Oimgx8/bItygMW3wHGbfc1lSutmYpuDg8XqSzOAAAAhjCBgwYJKoZIhvcNAQcGoHYwdAIBADBvBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDHiixPWB67X6kRqPFQIBEIBCcpJ2aHs0Srhzhvd6b2JO9fv63FdihVV8K3BPB7dgOYsxJi8tfLUrDKaHPFhOtHww6CSVgNb62Hh0/1YhUKnl0Gya').then(function(decoded) {
            // Should not get here
        }).catch(function (err) { should.exist(err); done(); });
	});
	
	it('should sign a payload that was issued 10 seconds before your local time', function() {
        return jwtkms.sign({foo: 'bar'}, {issued_at: new Date(Date.now() + 10000)}, process.env.KEY_ARN).then(function(new_token) {
            should.exist(new_token);
            token = new_token;
        });
    });

    it('should verify a token that was issued 10 seconds before your local time', function() {
        return jwtkms.verify(token).then(function(decoded) {
            should.exist(decoded);
            decoded.should.have.property('foo').eql('bar');
            decoded.should.have.property('iat');
        });
    });
    
    it('should throw a friendly error if passed a urn that is invalid', function() {
        return jwtkms.verify(token, { arn: 'asd' }).then(function(decoded) {
            // Should not get here
            throw new Error('Invalid token should not be verified.');
		}).catch(function(err) { 
			should.exist(err);
            err.should.be.instanceof(Error);
            
			return Promise.resolve();
		});
    });

	it('should verify a token wthat was issued 10 seconds before your local time', function() {
        return jwtkms.verify(token).then(function(decoded) {
            should.exist(decoded);
            decoded.should.have.property('foo').eql('bar');
            decoded.should.have.property('iat');

        });
    });
    
    it('should not verify a token if exipryTimeSeconds is less then the issued at timestamp', function() {
        return jwtkms.verify(token, { exipryTimeSeconds: 1 }).then(function() { 
            throw new Error('Should not verify');
        }, function(err) {
            should.exist(err);
            err.should.be.instanceof(Error);
        });
	});

	it('should sign a payload that was issued 1 hour before your local time', function() {
        return jwtkms.sign({foo: 'bar'}, {issued_at: new Date(Date.now() + 60*60*1000)}, process.env.KEY_ARN).then(function(new_token) {
            should.exist(new_token);
            token = new_token;
        });
    });
	
	it('should not verify a token that was issued 1 hour before your local time', function() {
        return jwtkms.verify(token).then(function(decoded) {
            // Should not get here
        }).catch(function (err) { should.exist(err); });
	});
	
	it('should throw a friendly error if passed a token that can\'t be decoded', function() {
        return jwtkms.verify('FOO_BAR').then(function(decoded) {
            throw new Error('Invalid token should not be verified.');
		}, function(err) { 
            should.exist(err);
            err.should.be.instanceof(Error);
			err.message.should.eql('Invalid token');
			
			return Promise.resolve();
		});
    });

    
});