function hextouint(h_str) {
    if (h_str.length % 2 !== 0) {
        throw "Invalid hexString";
    }
    var arr = new Uint8Array(h_str.length / 2);

    for (var j = 0; j < h_str.length; j += 2) {
        var byteVal = parseInt(h_str.substr(j, 2), 16);
        if (isNaN(byteVal)) {
            throw "Invalid hexString";
        }
        arr[j / 2] = byteVal;
    }

    return arr;
}

function hexstring(buf) {
    return [...new Uint8Array(buf)]
        .map(x => x.toString(16).padStart(2, '0'))
        .join('');
}
function arrToString(buf) {
    let s = '';
    const arr = new Uint8Array(buf);
    for (let j = 0; j < arr.length; j++) {
        s += String.fromCharCode(arr[j]);
    }
    return s;
}

function ascToUint(s) {
    var ch = [];
    for (var j = 0; j < s.length; ++j) {
        ch.push(s.charCodeAt(j));
    }
    return new Uint8Array(ch);
}

class eliptic_curve {
    constructor() {
        this.counter = window.crypto.getRandomValues(new Uint8Array(16));
    }

    async genrate_Keys() {
        await window.crypto.subtle.generateKey({
            name: "ECDH",
            namedCurve: "P-256"
        },
            true,
            ["deriveKey"]).then(async key => {
                this.publicKey = key.publicKey
                this.privateKey = key.privateKey

            })

        await window.crypto.subtle.deriveKey({
            name: "ECDH",
            namedCurve: "P-256",
            public: this.publicKey
        },
            this.privateKey,
            {
                name: "AES-CTR",
                length: 256
            },
            true,
            ["encrypt", "decrypt"]).then(async key => {
                this.deriveKey = key
            })

        this.keydata = await window.crypto.subtle.exportKey("jwk", this.deriveKey)
        this.privateKeyhold = await window.crypto.subtle.exportKey("jwk", this.publicKey)
        this.publicKeyhold = await window.crypto.subtle.exportKey("jwk", this.privateKey)
    }

    async encryption(m) {
        const data = {
            alg: this.keydata.alg,
            ext: this.keydata.ext,
            k: this.keydata.k,
            kty: this.keydata.kty,
        }

        let cipher = await window.crypto.subtle.importKey("jwk", data, "aes-ctr", false, ["encrypt"]).
            then(key => {
                return window.crypto.subtle.encrypt({
                    name: "aes-ctr",
                    counter: this.counter,
                    length: 128
                }, key, ascToUint(m))
            })

        return hexstring(cipher)
    }

    async decryption(msg) {
        const data = {
            alg: this.keydata.alg,
            ext: this.keydata.ext,
            k: this.keydata.k,
            kty: this.keydata.kty,
        }

        let plaintext = await window.crypto.subtle.importKey("jwk", data, "aes-ctr", false, ["decrypt"]).
            then(key => {
                return window.crypto.subtle.decrypt({
                    name: "aes-ctr",
                    counter: this.counter,
                    length: 128
                }, key, hextouint(msg))
            })

        return arrToString(plaintext)
    }
}
