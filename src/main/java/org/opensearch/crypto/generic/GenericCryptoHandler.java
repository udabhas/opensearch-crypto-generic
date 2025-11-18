/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.crypto.generic;

import org.opensearch.common.crypto.CryptoHandler;
import org.opensearch.common.crypto.DecryptedRangedStreamProvider;
import org.opensearch.common.crypto.EncryptedHeaderContentSupplier;
import org.opensearch.common.crypto.MasterKeyProvider;
import org.opensearch.common.io.InputStreamContainer;

import java.io.IOException;
import java.io.InputStream;

public class GenericCryptoHandler implements CryptoHandler<byte[], byte[]> {
    private final MasterKeyProvider keyProvider;
    private final Runnable onClose;

    public GenericCryptoHandler(MasterKeyProvider keyProvider, Runnable onClose) {
        this.keyProvider = keyProvider;
        this.onClose = onClose;
    }

    @Override
    public byte[] initEncryptionMetadata() {
        return new byte[0];
    }

    @Override
    public byte[] loadEncryptionMetadata(EncryptedHeaderContentSupplier supplier) throws IOException {
        return new byte[0];
    }

    @Override
    public long adjustContentSizeForPartialEncryption(byte[] cryptoContext, long contentSize) {
        return contentSize;
    }

    @Override
    public long estimateEncryptedLengthOfEntireContent(byte[] cryptoContext, long contentLength) {
        return contentLength;
    }

    @Override
    public long estimateDecryptedLength(byte[] cryptoContext, long contentLength) {
        return contentLength;
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
    public void close() {
        if (onClose != null) {
            onClose.run();
        }
    }
}
