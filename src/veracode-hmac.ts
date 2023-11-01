import * as sjcl from 'sjcl'
import * as util from 'util'
import * as crypto from 'crypto'


//module.exports.calculateAuthorizationHeader = calculateAuthorizationHeader;

const authorizationScheme = "VERACODE-HMAC-SHA-256";
const requestVersion = "vcode_request_version_1";
const nonceSize = 16;

function computeHashHex(message: string | sjcl.BitArray, key_hex: string) {
    let key_bits = sjcl.codec.hex.toBits(key_hex);
    let hmac_bits = (new sjcl.misc.hmac(key_bits, sjcl.hash.sha256)).mac(message);
    let hmac = sjcl.codec.hex.fromBits(hmac_bits);
    return hmac;
}

function calulateDataSignature(apiKeyBytes: string, nonceBytes: string | sjcl.BitArray, dateStamp: string | sjcl.BitArray, data: string | sjcl.BitArray) {
    let kNonce = computeHashHex(nonceBytes, apiKeyBytes);
    let kDate = computeHashHex(dateStamp, kNonce);
    let kSig = computeHashHex(requestVersion, kDate);
    let kFinal = computeHashHex(data, kSig);
    return kFinal;
}

function newNonce(nonceSize: number) {
    return crypto.randomBytes(nonceSize).toString('hex').toUpperCase();
}

function toHexBinary(input: string) {
    return sjcl.codec.hex.fromBits(sjcl.codec.utf8String.toBits(input));
}

export function calculateAuthorizationHeader(id: any, key: string, hostName: any, uriString: any, urlQueryParams: any, httpMethod: any) {
    uriString += urlQueryParams;
    let data = `id=${id}&host=${hostName}&url=${uriString}&method=${httpMethod}`;
    let dateStamp = Date.now().toString();
    let nonceBytes = newNonce(nonceSize);
    let dataSignature = calulateDataSignature(key, nonceBytes, dateStamp, data);
    let authorizationParam = `id=${id},ts=${dateStamp},nonce=${toHexBinary(nonceBytes)},sig=${dataSignature}`;
    let header = authorizationScheme + " " + authorizationParam;
    return header;
}