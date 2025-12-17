import { useState } from "react";
import axios from "axios";

interface ExchangePayload {
    kty: 'EC' | undefined;
    crv: 'P-256' | undefined;
    x: string;
    y: string;
}

interface BackendPublicKey {
    kty: 'EC' | undefined;
    crv: 'P-256' | undefined;
    x: string;
    y: string;
}

interface UseSendToBackendResult {
    exchangeECDH: (payload: ExchangePayload) => Promise<void>;
    deriveSecret: (frontendPrivateKey: CryptoKey) => Promise<CryptoKey>;
    backendPublicKey: BackendPublicKey | null;
    decodeInBackend: (iv: Uint8Array, encryptedBase64: string) => Promise<string>;
    error: string | null;
}

export default function useSendToBackend(): UseSendToBackendResult {
    const [backendPublicKey, setBackendPublicKey] =
        useState<BackendPublicKey | null>(null);

    const [error, setError] = useState<string | null>(null);

    const exchangeECDH = async (payload: ExchangePayload): Promise<void> => {
        try {
            const response = await axios.post<BackendPublicKey>(
                "http://localhost:3000/exchangeECDH",
                { data: payload }
            );

            setBackendPublicKey(response.data);
            console.log("Backend public key:", response.data);
        } catch (err) {
            console.error(err);
            setError("Error sending to backend");
        }
    };

    const deriveSecret = async (
        frontendPrivateKey: CryptoKey
    ): Promise<CryptoKey> => {
        if (!backendPublicKey) {
            throw new Error("Backend public key not available");
        }

        if (
            backendPublicKey.kty !== 'EC' ||
            backendPublicKey.crv !== 'P-256'
        ) {
            throw new Error("Invalid backend public key");
        }

        // 1️⃣ Import backend public key
        const importedBackendPublicKey = await crypto.subtle.importKey(
            'jwk',
            {
                kty: 'EC',
                crv: 'P-256',
                x: backendPublicKey.x,
                y: backendPublicKey.y,
                ext: true,
            },
            {
                name: 'ECDH',
                namedCurve: 'P-256',
            },
            false,
            []
        );

        // 2️⃣ Derive shared secret (bits)
        const sharedSecret = await crypto.subtle.deriveBits(
            {
                name: 'ECDH',
                public: importedBackendPublicKey,
            },
            frontendPrivateKey,
            256
        );

        // 3️⃣ Import as HKDF key material
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            sharedSecret,
            'HKDF',
            false,
            ['deriveKey']
        );

        // 4️⃣ Derive AES-GCM key
        const encoder = new TextEncoder();

        const aesKey = await crypto.subtle.deriveKey(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: encoder.encode('ecdh-demo-salt'),
                info: encoder.encode('aes-gcm-key'),
            },
            keyMaterial,
            {
                name: 'AES-GCM',
                length: 256,
            },
            true,
            ['encrypt', 'decrypt']
        );
        // const rawAes = await crypto.subtle.exportKey('raw', aesKey);

        // const hex = [...new Uint8Array(rawAes)]
        //     .map(b => b.toString(16).padStart(2, '0'))
        //     .join('');

        // console.log('AES KEY (hex):', hex);

        return aesKey;
    };

    const decodeInBackend = async (iv: Uint8Array, encryptedBase64: string): Promise<string> => {
        const ivBase64 = btoa(String.fromCharCode(...iv));
        const response = await axios.post<string>('http://localhost:3000/decode', {
            data: {
                iv: ivBase64,
                encryptedBase64,
            },
        }
        );

        return response.data;
    };


    return {
        exchangeECDH,
        deriveSecret,
        backendPublicKey,
        decodeInBackend,
        error,
    };
}
