import { Request, Response } from 'express';
import { webcrypto } from 'crypto';

const { subtle } = webcrypto;

const encoder = new TextEncoder();
const HKDF_SALT = encoder.encode('ecdh-demo-salt');
const HKDF_INFO = encoder.encode('aes-gcm-key');

export const ECDH = async (req: Request, res: Response) => {
    try {
        const { crv, kty, x, y } = req.body.data;

        if (
            kty !== 'EC' ||
            crv !== 'P-256' ||
            typeof x !== 'string' ||
            typeof y !== 'string'
        ) {
            return res.status(400).json({ error: 'Invalid ECDH parameters' });
        }

        const frontendPublicKey = await subtle.importKey(
            'jwk',
            { kty, crv, x, y, ext: true },
            { name: 'ECDH', namedCurve: 'P-256' },
            false,
            []
        );

        const backendKeyPair = await subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' },
            true,
            ['deriveBits']
        );

        const sharedSecret = await subtle.deriveBits(
            { name: 'ECDH', public: frontendPublicKey },
            backendKeyPair.privateKey,
            256
        );

        // 🔑 HKDF → AES
        const keyMaterial = await subtle.importKey(
            'raw',
            sharedSecret,
            'HKDF',
            false,
            ['deriveKey']
        );

        const aesKey = await subtle.deriveKey(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: HKDF_SALT,
                info: HKDF_INFO,
            },
            keyMaterial,
            {
                name: 'AES-GCM',
                length: 256,
            },
            true,
            ['encrypt', 'decrypt']
        );

        // DEBUG TEMPORAL
        const rawAes = await subtle.exportKey('raw', aesKey);
        console.log(
            'AES key (hex)',
            [...new Uint8Array(rawAes)]
                .map(b => b.toString(16).padStart(2, '0'))
                .join('')
        );

        const backendPublicJwk = await subtle.exportKey(
            'jwk',
            backendKeyPair.publicKey
        );

        res.json({
            kty: 'EC',
            crv: 'P-256',
            x: backendPublicJwk.x,
            y: backendPublicJwk.y,
        });
    } catch (error) {
        console.error(error);
        res.sendStatus(500);
    }
};

export const decode = async (req: Request, res: Response) => {
    try {
        const { iv, encryptedBase64 } = req.body.data;

        if (!iv || !encryptedBase64) {
            return res.status(400).json({ error: 'Missing iv or ciphertext' });
        }

        // 🔑 AES key derivada previamente (HEX)
        const aesKeyHex =
            '1335f9d09bbd8604cb68dac966040a523acd39ee71bf9c7baee6e07b1c3261d0';

        // 1️⃣ HEX → Uint8Array
        const aesKeyBytes = new Uint8Array(
            aesKeyHex.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16))
        );

        // 2️⃣ Import AES key
        const aesKey = await subtle.importKey(
            'raw',
            aesKeyBytes,
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );

        // 3️⃣ Base64 → Uint8Array (ciphertext)
        const ciphertext = Uint8Array.from(
            Buffer.from(encryptedBase64, 'base64')
        );

        // 4️⃣ Base64 → Uint8Array (IV)
        const ivBytes = Uint8Array.from(
            Buffer.from(iv, 'base64')
        );

        // 5️⃣ Decrypt
        const decrypted = await subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: ivBytes,
            },
            aesKey,
            ciphertext
        );

        const plaintext = new TextDecoder().decode(decrypted);

        console.log('✅ Decrypted text:', plaintext);

        res.json({ plaintext });

    } catch (error) {
        console.error('❌ Decrypt error:', error);
        res.status(400).json({ error: 'Decryption failed' });
    }
};