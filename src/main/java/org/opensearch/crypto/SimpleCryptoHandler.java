package org.opensearch.crypto;

import org.opensearch.common.crypto.CryptoHandler;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

public class SimpleCryptoHandler implements CryptoHandler<byte[], byte[]> {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
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
    public OutputStream createEncryptingStream(OutputStream stream, byte[] iv) {
        return new EncryptingOutputStream(stream, secretKey, iv);
    }

    @Override
    public byte[] loadDecryptionMetadata(InputStream stream) throws IOException {
        byte[] iv = new byte[GCM_IV_LENGTH];
        int read = stream.read(iv);
        if (read != GCM_IV_LENGTH) {
            throw new IOException("Failed to read IV");
        }
        return iv;
    }

    @Override
    public InputStream createDecryptingStream(InputStream stream, byte[] iv) {
        return new DecryptingInputStream(stream, secretKey, iv);
    }

    @Override
    public long estimateEncryptedSize(long plainTextSize, byte[] metadata) {
        return plainTextSize + GCM_TAG_LENGTH;
    }

    @Override
    public long estimateDecryptedSize(long encryptedSize, byte[] metadata) {
        return encryptedSize - GCM_TAG_LENGTH;
    }

    @Override
    public void close() throws IOException {
    }

    private static class EncryptingOutputStream extends OutputStream {
        private final OutputStream delegate;
        private final Cipher cipher;

        EncryptingOutputStream(OutputStream delegate, SecretKey key, byte[] iv) {
            this.delegate = delegate;
            try {
                this.cipher = Cipher.getInstance(ALGORITHM);
                GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
                cipher.init(Cipher.ENCRYPT_MODE, key, spec);
                delegate.write(iv);
            } catch (Exception e) {
                throw new RuntimeException("Failed to initialize encryption", e);
            }
        }

        @Override
        public void write(int b) throws IOException {
            write(new byte[] { (byte) b }, 0, 1);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            try {
                byte[] encrypted = cipher.update(b, off, len);
                if (encrypted != null) {
                    delegate.write(encrypted);
                }
            } catch (Exception e) {
                throw new IOException("Encryption failed", e);
            }
        }

        @Override
        public void close() throws IOException {
            try {
                byte[] finalBlock = cipher.doFinal();
                if (finalBlock != null) {
                    delegate.write(finalBlock);
                }
                delegate.close();
            } catch (Exception e) {
                throw new IOException("Failed to finalize encryption", e);
            }
        }
    }

    private static class DecryptingInputStream extends InputStream {
        private final InputStream delegate;
        private final Cipher cipher;
        private byte[] buffer;
        private int bufferPos;

        DecryptingInputStream(InputStream delegate, SecretKey key, byte[] iv) {
            this.delegate = delegate;
            try {
                this.cipher = Cipher.getInstance(ALGORITHM);
                GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
                cipher.init(Cipher.DECRYPT_MODE, key, spec);
            } catch (Exception e) {
                throw new RuntimeException("Failed to initialize decryption", e);
            }
        }

        @Override
        public int read() throws IOException {
            byte[] b = new byte[1];
            int result = read(b, 0, 1);
            return result == -1 ? -1 : b[0] & 0xFF;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (buffer != null && bufferPos < buffer.length) {
                int available = Math.min(len, buffer.length - bufferPos);
                System.arraycopy(buffer, bufferPos, b, off, available);
                bufferPos += available;
                return available;
            }

            byte[] encrypted = new byte[len + GCM_TAG_LENGTH];
            int read = delegate.read(encrypted);
            if (read == -1) {
                return -1;
            }

            try {
                byte[] decrypted = cipher.update(encrypted, 0, read);
                if (decrypted == null || decrypted.length == 0) {
                    return 0;
                }
                int toCopy = Math.min(len, decrypted.length);
                System.arraycopy(decrypted, 0, b, off, toCopy);
                if (decrypted.length > len) {
                    buffer = decrypted;
                    bufferPos = toCopy;
                }
                return toCopy;
            } catch (Exception e) {
                throw new IOException("Decryption failed", e);
            }
        }

        @Override
        public void close() throws IOException {
            try {
                cipher.doFinal();
                delegate.close();
            } catch (Exception e) {
                throw new IOException("Failed to finalize decryption", e);
            }
        }
    }
}
