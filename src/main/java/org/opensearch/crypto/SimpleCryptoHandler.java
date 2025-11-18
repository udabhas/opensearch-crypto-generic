/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.crypto;

import org.opensearch.common.crypto.CryptoHandler;
import org.opensearch.common.crypto.DecryptedRangedStreamProvider;
import org.opensearch.common.crypto.EncryptedHeaderContentSupplier;
import org.opensearch.common.io.InputStreamContainer;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;

public class SimpleCryptoHandler implements CryptoHandler<byte[], byte[]> {
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;
    private final SecretKey secretKey;

    public SimpleCryptoHandler() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            this.secretKey = keyGen.generateKey();
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize crypto handler", e);
        }
    }

    @Override
    public byte[] initEncryptionMetadata() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    @Override
    public byte[] loadEncryptionMetadata(EncryptedHeaderContentSupplier supplier) throws IOException {
        return supplier.supply(0, GCM_IV_LENGTH);
    }

    @Override
    public long adjustContentSizeForPartialEncryption(byte[] cryptoContext, long contentSize) {
        return contentSize;
    }

    @Override
    public long estimateEncryptedLengthOfEntireContent(byte[] cryptoContext, long contentLength) {
        return contentLength + GCM_IV_LENGTH + GCM_TAG_LENGTH;
    }

    @Override
    public long estimateDecryptedLength(byte[] cryptoContext, long contentLength) {
        return contentLength - GCM_IV_LENGTH - GCM_TAG_LENGTH;
    }

    @Override
    public InputStreamContainer createEncryptingStream(byte[] encryptionMetadata, InputStreamContainer stream) {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public InputStreamContainer createEncryptingStreamOfPart(byte[] cryptoContext, InputStreamContainer stream, int totalStreams, int streamIdx) {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public InputStream createDecryptingStream(InputStream encryptingStream) {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public DecryptedRangedStreamProvider createDecryptingStreamOfRange(byte[] cryptoContext, long startPosOfRawContent, long endPosOfRawContent) {
        long[] adjustedRange = new long[] { startPosOfRawContent, endPosOfRawContent };
        return new DecryptedRangedStreamProvider(adjustedRange, stream -> stream);
    }

    @Override
    public void close() throws IOException {
    }
}
