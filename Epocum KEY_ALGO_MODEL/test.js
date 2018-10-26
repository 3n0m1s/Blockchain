// TEST CRIPTOGRAFY ----------------------------------------------------

var EC = require('elliptic').ec;
var BN = require('bn.js');
var ec = new EC('secp256k1');
//const keccak256 = require('js-sha3').keccak256;
//const createKeccakHash = require('keccak')

var util = require('./util.js');

var mnem = util.generateMnemonic();
console.log(mnem);

var password = 'test';
var pkey2 = util.generatePrivateKey(mnem);

a = '00000000000000000001111111111111'

i = util.toBuffer(pkey2);

console.log("PK length: "+i.length)


console.log("test length: "+a.length)

//PRIVATE KEY

var privateKey=Buffer.alloc(32, 0);

privateKey[31]= 1; //impostare buffer derivato da password + mnemonic seed

console.log("PK::"+privateKey.toString('hex'))

var G = ec.g; // Generator point
var pk = new BN('1'); // private key as big number

var pubPoint=G.mul(pk); // EC multiplication to determine public point

var x = pubPoint.getX().toBuffer(); //32 bit x co-ordinate of public point
var y = pubPoint.getY().toBuffer(); //32 bit y co-ordinate of public point 

var publicKey =Buffer.concat([x,y])

console.log("public key::"+publicKey.toString('hex'))

const address = util.keccak256(publicKey) // keccak256 hash of  publicKey

const buf2 = Buffer.from(address, 'hex');

console.log("Epocum Adress:::"+"EPMx"+buf2.slice(-20).toString('hex')) // take lat 20 bytes as ethereum adress

// END TEST CRIPTOGRAFY ----------------------------------------------------

//TESTING UTIL -------------------------------------------------------------

//SIGN data with private and give back the public checking if the signature is derived by the original address.

var privkey = new Buffer(privateKey, 'hex');
var data = util.keccak('transazione') //get the hash direct buffered
var vrs = util.ecsign(data, privkey);
var pubkey = util.ecrecover(data, vrs.v, vrs.r, vrs.s);

// Check !
console.log('Signature valida: ' + util.isValidSignature(vrs.v, vrs.r, vrs.s))
console.log('Public key valida: ' + util.isValidPublic(pubkey))
console.log('Signature derivata dalla chiave privata che genera l indirizzo: ' + 'EPMx'+util.publicToAddress(pubkey).toString('hex'));
console.log('validita indirizzo: '+ util.isValidAddress('EPMx'+util.publicToAddress(pubkey).toString('hex')));
var check1 = pubkey.toString('hex') == util.privateToPublic(privkey).toString('hex');
var check2 = util.publicToAddress(pubkey).toString('hex') == util.privateToAddress(privkey).toString('hex');
// Check is ok !
console.log(check1,check2);

