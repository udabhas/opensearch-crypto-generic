/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.crypto;

import org.opensearch.common.crypto.CryptoHandler;
import org.opensearch.common.crypto.MasterKeyProvider;
import org.opensearch.plugins.CryptoPlugin;
import org.opensearch.plugins.Plugin;

public class GenericCryptoPlugin extends Plugin implements CryptoPlugin<byte[], byte[]> {

    @Override
    public CryptoHandler<byte[], byte[]> getOrCreateCryptoHandler(
        MasterKeyProvider keyProvider,
        String keyProviderName,
        String keyProviderType,
        Runnable onClose
    ) {
        // Pass the KMS MasterKeyProvider to SimpleCryptoHandler for envelope encryption
        return new SimpleCryptoHandler(keyProvider);
    }
}
