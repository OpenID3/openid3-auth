import crypto from "crypto";

const key = crypto.generateKeyPair("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
    },
    privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
    },
}, (err, publicKey, privateKey) => {
        console.log(publicKey);
        console.log(privateKey);
    }
);

