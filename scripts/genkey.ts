import {ethers} from "ethers";
import {NDKPrivateKeySigner} from "@nostr-dev-kit/ndk";

const wallet = ethers.Wallet.createRandom();
console.log("private key: ", wallet.privateKey);
console.log("public key: ", wallet.publicKey);
console.log("address: ", wallet.address);

const ndkSigner = new NDKPrivateKeySigner(
    wallet.privateKey.slice(2) /* remove 0x */,
);
ndkSigner.user().then(user => {
    console.log("nostr npub address: ", user.npub);
    console.log("nostr pub key: ", user.pubkey);
})
