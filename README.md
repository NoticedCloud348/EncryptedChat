# EncryptedChat  

**EncryptedChat** is a secure messaging application designed to ensure user privacy and data protection.  

## Features  
- **End-to-End Encryption (E2EE):** All messages are fully encrypted, ensuring that only the intended recipient can read them.  
- **Anti-MITM Protection:** Robust mechanisms are in place to prevent Man-in-the-Middle (MITM) attacks, keeping your communication safe.  
- **Private Rooms:** Communication takes place in private rooms identified by a unique `channel_id` and protected with a password.  

### Room System  
- Each room is identified by a **randomly generated `channel_id`** composed of **10 bytes**.  
- Rooms are secured with a **password**, which can either be user-defined or **randomly generated** in **Base64 format** with a length of **32 characters**.  
- Each room supports a maximum of **2 connections**, including the room creator. This prevents unauthorized third parties from joining the room.  

## Getting Started  

### Certificate Setup  
To use EncryptedChat, you need SSL/TLS certificates. You have two options:  

1. **Modify the certificate paths in the code:**  
   Update the paths for `key.pem` and `cert.pem` in the server code to point to your existing certificates.  

2. **Create a `cert` directory:**  
   Place the following files in a folder named `cert` in the project root:  
   - `key.pem`: The private key file.  
   - `cert.pem`: The certificate file.  

### Client Configuration  
- Change the server IP address in the client code to match your server’s IP.  

## Usage  
1. Start the server.  
2. Configure the client with the correct server IP.  
3. Create a room by specifying a password or letting the system generate one.  
4. Share the `channel_id` and password securely with the intended participant.  
5. Enjoy secure, encrypted messaging!  

## Notes  
- Ensure your certificates are valid and properly secured.  
- Randomly generated passwords and room IDs increase security, but always share them securely.  
- Unauthorized connections are automatically rejected to maintain privacy.
- A room has a maximum of 2 people to ensure safety and privacy

## Disclaimer  
EncryptedChat is designed for educational and private use. The developers are not responsible for improper use or vulnerabilities arising from user misconfiguration.  
