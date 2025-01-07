document.addEventListener('DOMContentLoaded', (event) => {
    const socket = io();
    let publicKey;
    let aesKey;

    socket.on('connect', () => {
        console.log('Connected to server');
    });

    socket.on('public_key', (data) => {
        publicKey = data.public_key;
        console.log('Received public key:', publicKey);
    });

    socket.on('message', (data) => {
        console.log('Received message:', data);
        const chatBox = document.getElementById('chat');
        const messageElement = document.createElement('p');
        messageElement.textContent = data.decrypted_message;
        chatBox.appendChild(messageElement);
    });

    socket.on('error', (data) => {
        console.error('Error:', data.message);
    });

    async function generateAESKey() {
        return crypto.subtle.generateKey(
            {
                name: "AES-GCM",
                length: 256,
            },
            true,
            ["encrypt", "decrypt"]
        );
    }

    async function encryptMessage(message) {
        const encodedMessage = new TextEncoder().encode(message);
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encryptedMessage = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv,
            },
            aesKey,
            encodedMessage
        );
        return {
            message: btoa(String.fromCharCode(...new Uint8Array(encryptedMessage))),
            nonce: btoa(String.fromCharCode(...iv))
        };
    }

    async function decryptMessage(encryptedMessage, nonce) {
        const decodedMessage = Uint8Array.from(atob(encryptedMessage), c => c.charCodeAt(0));
        const decodedNonce = Uint8Array.from(atob(nonce), c => c.charCodeAt(0));
        const decryptedMessage = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: decodedNonce,
            },
            aesKey,
            decodedMessage
        );
        return new TextDecoder().decode(decryptedMessage);
    }

    async function sendMessage() {
        const message = document.getElementById('message').value;
        const sid = socket.id;
        if (!aesKey) {
            try {
                aesKey = await generateAESKey();
                const exportedAESKey = await window.crypto.subtle.exportKey("raw", aesKey);
                const encryptedAESKey = await encryptAESKey(exportedAESKey);
                console.log('Sending AES key:', encryptedAESKey);
                socket.emit('aes_key', { aes_key: encryptedAESKey, sid: sid });
            } catch (error) {
                console.error('Error generating or sending AES key:', error);
                return;
            }
        }
        try {
            const encryptedMessage = await encryptMessage(message);
            console.log('Sending message:', encryptedMessage);
            socket.emit('message', { message: encryptedMessage.message, nonce: encryptedMessage.nonce, sid: sid });

            // Display the message on the sender's UI
            const chatBox = document.getElementById('chat');
            const messageElement = document.createElement('p');
            messageElement.textContent = message;
            chatBox.appendChild(messageElement);
        } catch (error) {
            console.error('Error encrypting or sending message:', error);
        }
    }

    async function encryptAESKey(aesKey) {
        try {
            const publicKeyPem = publicKey.split('\n').slice(1, -1).join('');
            console.log('Public key PEM:', publicKeyPem);
            
            const importedPublicKey = await window.crypto.subtle.importKey(
                "spki",
                Uint8Array.from(atob(publicKeyPem), c => c.charCodeAt(0)),
                {
                    name: "RSA-OAEP",
                    hash: "SHA-256"
                },
                false,
                ["encrypt"]
            );
            console.log('Imported public key:', importedPublicKey);
            
            const encryptedAESKey = await window.crypto.subtle.encrypt(
                {
                    name: "RSA-OAEP"
                },
                importedPublicKey,
                aesKey
            );
            console.log('Encrypted AES key:', encryptedAESKey);
            
            return btoa(String.fromCharCode(...new Uint8Array(encryptedAESKey)));
        } catch (error) {
            console.error('Error encrypting AES key:', error);
            throw error;
        }
    }

    // Event listener for sending messages
    document.getElementById('sendButton').addEventListener('click', sendMessage);
});