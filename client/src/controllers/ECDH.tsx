type KeyPair = {
    publicKeyJwk: JsonWebKey;
    privateKey: CryptoKey;
    privateKeyJwk: JsonWebKey;
};

export async function generateFrontendKeyPair(): Promise<KeyPair> {
    const keyPair = await crypto.subtle.generateKey(
        {
            name: "ECDH",
            namedCurve: "P-256",
        },
        true, // solo debug
        ["deriveKey", "deriveBits"]
    );

    const publicKeyJwk = await crypto.subtle.exportKey(
        "jwk",
        keyPair.publicKey
    ) as JsonWebKey;

    const privateKeyJwk = await crypto.subtle.exportKey(
        "jwk",
        keyPair.privateKey
    ) as JsonWebKey;

    return {
        publicKeyJwk,
        privateKey: keyPair.privateKey,
        privateKeyJwk,
    };
}
