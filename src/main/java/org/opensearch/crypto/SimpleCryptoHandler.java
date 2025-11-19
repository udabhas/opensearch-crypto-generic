/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.crypto;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.crypto.CryptoHandler;
import org.opensearch.common.crypto.DataKeyPair;
import org.opensearch.common.crypto.DecryptedRangedStreamProvider;
import org.opensearch.common.crypto.EncryptedHeaderContentSupplier;
import org.opensearch.common.crypto.MasterKeyProvider;
import org.opensearch.common.io.InputStreamContainer;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;

/**
 * SimpleCryptoHandler with KMS envelope encryption support.
 * Uses AES-CTR mode with 16-byte IV.
 * 
 * Encrypted data format:
 * [4-byte encrypted key length][encrypted data key][16-byte IV][ciphertext]
 */
public class SimpleCryptoHandler implements CryptoHandler<byte[], byte[]> {
    private static final Logger logger = LogManager.getLogger(SimpleCryptoHandler.class);
    private static final int CTR_IV_LENGTH = 16;
    private static final int KEY_LENGTH_PREFIX_SIZE = 4;
    private static final int ESTIMATED_ENCRYPTED_KEY_SIZE = 220; // AWS KMS encrypted key is typically ~200 bytes
    
    private final MasterKeyProvider keyProvider;

    public SimpleCryptoHandler(MasterKeyProvider keyProvider) {
        this.keyProvider = keyProvider;
        logger.info("SimpleCryptoHandler initialized with KMS MasterKeyProvider");
    }

    @Override
    public byte[] initEncryptionMetadata() {
        byte[] iv = new byte[CTR_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    @Override
    public byte[] loadEncryptionMetadata(EncryptedHeaderContentSupplier supplier) throws IOException {
        // First read the encrypted key length prefix
        byte[] lengthBytes = supplier.supply(0, KEY_LENGTH_PREFIX_SIZE);
        int encryptedKeyLength = readInt(lengthBytes);
        
        // Skip over: length prefix + encrypted key, then read IV
        long ivOffset = KEY_LENGTH_PREFIX_SIZE + encryptedKeyLength;
        return supplier.supply(ivOffset, CTR_IV_LENGTH);
    }

    @Override
    public long adjustContentSizeForPartialEncryption(byte[] cryptoContext, long contentSize) {
        return contentSize;
    }

    @Override
    public long estimateEncryptedLengthOfEntireContent(byte[] cryptoContext, long contentLength) {
        // Format: [4-byte length][~220-byte encrypted key][16-byte IV][ciphertext]
        return KEY_LENGTH_PREFIX_SIZE + ESTIMATED_ENCRYPTED_KEY_SIZE + CTR_IV_LENGTH + contentLength;
    }

    @Override
    public long estimateDecryptedLength(byte[] cryptoContext, long contentLength) {
        // Subtract the envelope encryption overhead
        return contentLength - KEY_LENGTH_PREFIX_SIZE - ESTIMATED_ENCRYPTED_KEY_SIZE - CTR_IV_LENGTH;
    }

    @Override
    public InputStreamContainer createEncryptingStream(byte[] encryptionMetadata, InputStreamContainer stream) {
        try {
            logger.info("[ENCRYPT] Starting AES-CTR encryption with KMS envelope");

            // 1. Generate data key from KMS
            DataKeyPair dataKey = keyProvider.generateDataPair();
            byte[] plaintextKey = dataKey.getPlaintext();
            byte[] encryptedKey = dataKey.getEncrypted();
            logger.info("[ENCRYPT] Generated KMS data key - plaintext: {} bytes, encrypted: {} bytes", 
                plaintextKey.length, encryptedKey.length);

            // 2. Read plaintext data
            byte[] plaintext = stream.getInputStream().readAllBytes();
            logger.info("[ENCRYPT] Read plaintext: {} bytes", plaintext.length);

            // 3. Encrypt data with AES-CTR using the plaintext data key
            SecretKeySpec keySpec = new SecretKeySpec(plaintextKey, "AES");
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            IvParameterSpec ivSpec = new IvParameterSpec(encryptionMetadata);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            byte[] ciphertext = cipher.doFinal(plaintext);
            logger.info("[ENCRYPT] Encrypted ciphertext: {} bytes", ciphertext.length);

            // 4. Build output with envelope: [length][encrypted_key][IV][ciphertext]
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            writeInt(output, encryptedKey.length);
            output.write(encryptedKey);
            output.write(encryptionMetadata);  // IV
            output.write(ciphertext);

            byte[] result = output.toByteArray();
            logger.info("[ENCRYPT] Total output with KMS envelope: {} bytes", result.length);

            return new InputStreamContainer(
                new ByteArrayInputStream(result),
                result.length,
                stream.getOffset()
            );
        } catch (Exception e) {
            logger.error("[ENCRYPT] Encryption failed", e);
            throw new RuntimeException("Encryption failed", e);
        }
    }

    @Override
    public InputStreamContainer createEncryptingStreamOfPart(byte[] cryptoContext, InputStreamContainer stream, int totalStreams, int streamIdx) {
        return createEncryptingStream(cryptoContext, stream);
    }

    @Override
    public InputStream createDecryptingStream(InputStream encryptingStream) {
        try {
            logger.info("[DECRYPT] Starting AES-CTR decryption with KMS envelope");
            
            // 1. Read encrypted data key length (4 bytes)
            byte[] lengthBytes = encryptingStream.readNBytes(KEY_LENGTH_PREFIX_SIZE);
            int encKeyLength = readInt(lengthBytes);
            logger.info("[DECRYPT] Encrypted key length: {} bytes", encKeyLength);
            
            // 2. Read encrypted data key
            byte[] encryptedKey = encryptingStream.readNBytes(encKeyLength);
            if (encryptedKey.length < encKeyLength) {
                throw new IOException("Insufficient data for encrypted key");
            }
            logger.info("[DECRYPT] Read encrypted key: {} bytes", encryptedKey.length);
            
            // 3. Call KMS to decrypt the data key
            byte[] plaintextKey = keyProvider.decryptKey(encryptedKey);
            logger.info("[DECRYPT] Decrypted data key from KMS: {} bytes", plaintextKey.length);
            
            // 4. Read IV
            byte[] iv = encryptingStream.readNBytes(CTR_IV_LENGTH);
            if (iv.length < CTR_IV_LENGTH) {
                throw new IOException("Insufficient data for IV");
            }
            logger.info("[DECRYPT] Read IV: {} bytes", iv.length);
            
            // 5. Read ciphertext
            byte[] ciphertext = encryptingStream.readAllBytes();
            logger.info("[DECRYPT] Read ciphertext: {} bytes", ciphertext.length);
            
            // 6. Decrypt with the data key from KMS
            SecretKeySpec keySpec = new SecretKeySpec(plaintextKey, "AES");
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            byte[] plaintext = cipher.doFinal(ciphertext);
            logger.info("[DECRYPT] Decrypted plaintext: {} bytes", plaintext.length);
            
            return new ByteArrayInputStream(plaintext);
        } catch (Exception e) {
            logger.error("[DECRYPT] Decryption failed", e);
            throw new RuntimeException("Decryption failed", e);
        }
    }

    @Override
    public DecryptedRangedStreamProvider createDecryptingStreamOfRange(byte[] cryptoContext, long startPosOfRawContent, long endPosOfRawContent) {
        long[] adjustedRange = new long[] { startPosOfRawContent, endPosOfRawContent };
        return new DecryptedRangedStreamProvider(adjustedRange, stream -> stream);
    }

    @Override
    public void close() throws IOException {
        // Nothing to close
    }
    
    // Helper methods for reading/writing integers
    private void writeInt(ByteArrayOutputStream out, int value) throws IOException {
        out.write((value >>> 24) & 0xFF);
        out.write((value >>> 16) & 0xFF);
        out.write((value >>> 8) & 0xFF);
        out.write(value & 0xFF);
    }
    
    private int readInt(byte[] bytes) {
        if (bytes.length < 4) {
            throw new IllegalArgumentException("Need 4 bytes to read int");
        }
        return ((bytes[0] & 0xFF) << 24) |
               ((bytes[1] & 0xFF) << 16) |
               ((bytes[2] & 0xFF) << 8) |
               (bytes[3] & 0xFF);
    }
}
