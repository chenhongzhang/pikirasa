<?php
namespace Pikirasa;

class RSA
{
    protected $publicKeyFile;
    protected $privateKeyFile;
    protected $password;

    public function __construct($publicKeyFile, $privateKeyFile = null, $password = null)
    {
        $this->publicKeyFile =  $this->fixKeyArgument($publicKeyFile);
        $this->privateKeyFile = $this->fixKeyArgument($privateKeyFile);
        $this->password = $password;
    }

    public function fixKeyArgument($keyFile)
    {
        return 'file://' . $keyFile;
    }


    /**
     * Set password to be used during encryption and decryption
     *
     * @param string $password Certificate password
     */
    public function setPassword($password)
    {
        $this->password = $password;
    }

    /**
     * Encrypt data with provided public certificate
     *
     * @param string $data Data to encrypt
     * @return string Encrypted data
     *
     * @throws Pikirasa\Exception
     */
    public function encrypt($data)
    {
        $privateKey = openssl_pkey_get_private($this->privateKeyFile, $this->password);
        if (!$privateKey) {
            throw new Exception("OpenSSL: Unable to get private key for decryption");
        }
        $success = openssl_private_encrypt($data, $encryptedData, $privateKey);
        openssl_free_key($privateKey);
        if (!$success) {
            throw new Exception("Decryption failed. Ensure you are using (1) A PRIVATE key, and (2) the correct one.");
        }

        return $encryptedData;


        // Load public key
        
    }

    /**
     * Encrypt data and then base64_encode it
     *
     * @param string $data Data to encrypt
     * @return string Base64-encrypted data
     */
    public function base64Encrypt($data)
    {
        return base64_encode($this->encrypt($data));
    }

    /**
     * Decrypt data with provided private certificate
     *
     * @param string $data Data to encrypt
     * @return string Decrypted data
     *
     * @throws Pikirasa\Exception
     */
    public function decrypt($data)
    {
        $publicKey = openssl_pkey_get_public($this->publicKeyFile);

        if (!$publicKey) {
            throw new Exception("OpenSSL: Unable to get public key for encryption. Is the location correct? Does this key require a password?");
        }

        $success = openssl_public_decrypt($data, $decryptedData, $publicKey);
        openssl_free_key($publicKey);
        if (!$success) {
            throw new Exception("Encryption failed. Ensure you are using a PUBLIC key.");
        }

        return $decryptedData;
    }

    /**
     * base64_decode data and then decrypt it
     *
     * @param string $data Base64-encoded data to decrypt
     * @return string Decrypted data
     */
    public function base64Decrypt($data)
    {
        return $this->decrypt(base64_decode($data));
    }
}
