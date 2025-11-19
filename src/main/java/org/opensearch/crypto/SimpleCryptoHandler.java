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
import org.opensearch.common.crypto.DecryptedRangedStreamProvider;
import org.opensearch.common.crypto.EncryptedHeaderContentSupplier;
import org.opensearch.common.crypto.MasterKeyProvider;
import org.opensearch.common.io.InputStreamContainer;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * SimpleCryptoHandler for testing index-level encryption.
 * Uses deterministic key derived from KMS ARN to work across restarts.
 * Uses AES-CTR mode with 16-byte IV.
 */
public class SimpleCryptoHandler implements CryptoHandler<byte[], byte[]> {
    private static final Logger logger = LogManager.getLogger(SimpleCryptoHandler.class);
    private static final int CTR_IV_LENGTH = 16;
    private final SecretKeySpec secretKey;
    private final String keyId;

    public SimpleCryptoHandler(MasterKeyProvider keyProvider) {
        this.keyId = keyProvider.getKeyId();
        // Create deterministic key from KMS ARN using SHA-256 hash
        this.secretKey = createDeterministicKey(keyId);
        logger.info("SimpleCryptoHandler initialized with deterministic key from KMS ARN: {}", keyId);
    }
    
    /**
     * Creates a deterministic 256-bit AES key from the KMS ARN.
     * This ensures the same key is used across OpenSearch restarts.
     */
    private SecretKeySpec createDeterministicKey(String kmsArn) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(kmsArn.getBytes(StandardCharsets.UTF_8));
            return new SecretKeySpec(hash, "AES");
        } catch (Exception e) {
            throw new RuntimeException("Failed to create deterministic key", e);
        }
    }

    @Override
    public byte[] initEncryptionMetadata() {
        byte[] iv = new byte[CTR_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    @Override
    public byte[] loadEncryptionMetadata(EncryptedHeaderContentSupplier supplier) throws IOException {
        return supplier.supply(0, CTR_IV_LENGTH);
    }

    @Override
    public long adjustContentSizeForPartialEncryption(byte[] cryptoContext, long contentSize) {
        return contentSize;
    }

    @Override
    public long estimateEncryptedLengthOfEntireContent(byte[] cryptoContext, long contentLength) {
        return CTR_IV_LENGTH + contentLength;
    }

    @Override
    public long estimateDecryptedLength(byte[] cryptoContext, long contentLength) {
        return contentLength - CTR_IV_LENGTH;
    }

    @Override
    public InputStreamContainer createEncryptingStream(byte[] encryptionMetadata, InputStreamContainer stream) {
        try {
            logger.info("[ENCRYPT] Starting AES-CTR encryption, key derived from: {}", keyId);

            byte[] plaintext = stream.getInputStream().readAllBytes();
            logger.info("[ENCRYPT] Read plaintext: {} bytes", plaintext.length);

            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            IvParameterSpec ivSpec = new IvParameterSpec(encryptionMetadata);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            byte[] ciphertext = cipher.doFinal(plaintext);
            logger.info("[ENCRYPT] Encrypted ciphertext: {} bytes", ciphertext.length);

            byte[] output = new byte[CTR_IV_LENGTH + ciphertext.length];
            System.arraycopy(encryptionMetadata, 0, output, 0, CTR_IV_LENGTH);
            System.arraycopy(ciphertext, 0, output, CTR_IV_LENGTH, ciphertext.length);

            logger.info("[ENCRYPT] Total output: {} bytes", output.length);
            return new InputStreamContainer(
                new ByteArrayInputStream(output),
                output.length,
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
            logger.info("[DECRYPT] Starting AES-CTR decryption, key derived from: {}", keyId);
            
            byte[] iv = new byte[CTR_IV_LENGTH];
            int ivRead = encryptingStream.readNBytes(iv, 0, CTR_IV_LENGTH);
            logger.info("[DECRYPT] Read IV: {} bytes", ivRead);
            if (ivRead < CTR_IV_LENGTH) {
                throw new IOException("Insufficient data for IV");
            }
            
            byte[] ciphertext = encryptingStream.readAllBytes();
            logger.info("[DECRYPT] Read ciphertext: {} bytes", ciphertext.length);
            
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
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
}
