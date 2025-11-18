/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.crypto.generic;

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
        return new GenericCryptoHandler(keyProvider, onClose);
    }
}
