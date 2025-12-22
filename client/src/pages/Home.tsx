import Button from '../components/Button.tsx';
import { generateFrontendKeyPair } from '../controllers/ECDH.tsx';
import { useState, useEffect, useRef } from 'react';
import useSendToBackend from '../hooks/useSendToBackend.tsx';

type KeyPair = {
    publicKeyJwk: JsonWebKey;
    privateKey: CryptoKey;
    privateKeyJwk: JsonWebKey;
};

export default function Home() {
    const { exchangeECDH, deriveSecret, backendPublicKey, decodeInBackend } = useSendToBackend();
    const [keyPair, setKeyPair] = useState<KeyPair | null>(null);
    const [aesKey, setAesKey] = useState<CryptoKey | null>(null);
    const [message, setMessage] = useState<string | null>(null);
    const [encryptedMessage, setEncryptedMessage] = useState<string | null>(null);
    const [decryptedMessage, setDecryptedMessage] = useState<string | null>(null);

    // Usar useRef para mantener el IV entre renderizados
    const ivRef = useRef<Uint8Array | null>(null);

    const frontendECDH = async () => {
        const keys = await generateFrontendKeyPair();
        setKeyPair(keys);
    };

    useEffect(() => {
        if (!keyPair?.publicKeyJwk?.x || !keyPair?.publicKeyJwk?.y) return;
        exchangeECDH({
            crv: keyPair.publicKeyJwk.crv,
            kty: keyPair.publicKeyJwk.kty,
            x: keyPair.publicKeyJwk.x,
            y: keyPair.publicKeyJwk.y,
        });
    }, [keyPair, exchangeECDH]);

    useEffect(() => {
        if (!keyPair?.privateKey) return;
        if (!backendPublicKey) return;

        const derive = async () => {
            const aes = await deriveSecret(keyPair.privateKey);
            setAesKey(aes);
        };

        derive();
    }, [keyPair, backendPublicKey]);

    const handleInputChange = (event: React.ChangeEvent<HTMLInputElement>) => {
        setMessage(event.target.value);
    };

    const showAES = async () => {
        if (aesKey) {
            const rawAes = await crypto.subtle.exportKey('raw', aesKey);

            const hex = [...new Uint8Array(rawAes)]
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');

            console.log('AES KEY (hex):', hex);
        }
    }

    useEffect(() => {
        if (aesKey) showAES();
    }, [aesKey]);

    // Función para obtener un IV (lo genera solo la primera vez)
    const getIV = () => {
        if (!ivRef.current) {
            ivRef.current = crypto.getRandomValues(new Uint8Array(12)); // 12 bytes para AES-GCM
        }
        return ivRef.current;
    };

    const encryptor = async (data: string) => {
        if (aesKey) {
            const iv = getIV();

            const encrypted = await crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    iv
                },
                aesKey,
                new TextEncoder().encode(data)
            );
            const encryptedArray = new Uint8Array(encrypted);
            const base64 = btoa(String.fromCharCode(...encryptedArray));
            setEncryptedMessage(base64);
        }
    };

    const decryptor = async (encryptedBase64: string) => {
        if (aesKey) {
            try {
                if (!ivRef.current) {
                    throw new Error("No hay IV disponible. Debes encriptar primero.");
                }

                const iv = ivRef.current;

                // Decodificar Base64
                const binaryString = atob(encryptedBase64);
                const encryptedArray = new Uint8Array(binaryString.length);

                for (let i = 0; i < binaryString.length; i++) {
                    encryptedArray[i] = binaryString.charCodeAt(i);
                }

                // Desencriptar
                const decrypted = await crypto.subtle.decrypt(
                    {
                        name: "AES-GCM",
                        iv: iv
                    },
                    aesKey,
                    encryptedArray
                );

                // Convertir a string
                const decryptedText = new TextDecoder().decode(decrypted);
                setDecryptedMessage(decryptedText);
                return decryptedText;

            } catch (error) {
                console.log("Longitud:", encryptedBase64.length);
                throw error;
            }
        } else {
            throw new Error("No hay clave AES disponible");
        }
    };

    return (
        <>
            <h1>Home</h1>
            <Button text="Click me" onClick={frontendECDH} />

            {keyPair && (
                <div>
                    <p>Frontend PublicKey x: {keyPair.publicKeyJwk.x}</p>
                    <p>Frontend PublicKey y: {keyPair.publicKeyJwk.y}</p>
                    <p>AES key: {aesKey ? 'yes' : 'no'}</p>
                </div>
            )}

            <div>
                <input type="text" name="message" onChange={handleInputChange} />
                <Button text="Encrypt" onClick={() => encryptor(message || '')} />
                <p>Encrypted message: {encryptedMessage}</p>
            </div>

            <div>
                <Button text="Decrypt" onClick={() => {
                    if (ivRef.current && encryptedMessage) {
                        decryptor(encryptedMessage).catch(console.error);
                        decodeInBackend(ivRef.current, encryptedMessage);
                    }
                }} />
                <p>{decryptedMessage || ''}</p>
            </div>
        </>
    );
}