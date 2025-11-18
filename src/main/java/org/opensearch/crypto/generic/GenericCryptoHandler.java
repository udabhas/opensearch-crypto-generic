/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.crypto.generic;

import org.opensearch.common.crypto.CryptoHandler;
import org.opensearch.common.crypto.MasterKeyProvider;
import org.opensearch.common.io.InputStreamContainer;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.security.SecureRandom;

public class GenericCryptoHandler implements CryptoHandler<byte[], byte[]> {
    private final MasterKeyProvider keyProvider;
    private final Runnable onClose;
    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_IV_LENGTH = 12;
    private static final String ALGORITHM = "AES/GCM/NoPadding";

    public GenericCryptoHandler(MasterKeyProvider keyProvider, Runnable onClose) {
        this.keyProvider = keyProvider;
        this.onClose = onClose;
    }

    @Override
    public InputStreamContainer createEncryptingStream(InputStreamContainer stream) {
        try {
            byte[] iv = new byte[GCM_IV_LENGTH];
            new SecureRandom().nextBytes(iv);
            
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(keyProvider.getKey(), "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            
            InputStream ivStream = new ByteArrayInputStream(iv);
            InputStream encryptedStream = new CipherInputStream(stream.getInputStream(), cipher);
            InputStream combined = new SequenceInputStream(ivStream, encryptedStream);
            
            return new InputStreamContainer(combined, stream.getContentLength() + GCM_IV_LENGTH + 16, stream.getOffset());
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    @Override
    public InputStream createDecryptingStream(InputStream stream) {
        try {
            byte[] iv = new byte[GCM_IV_LENGTH];
            stream.read(iv);
            
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(keyProvider.getKey(), "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            
            return new CipherInputStream(stream, cipher);
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed", e);
        }
    }

    @Override
    public void close() {
        if (onClose != null) {
            onClose.run();
        }
    }
}
