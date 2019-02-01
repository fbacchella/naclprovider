package fr.loghub.naclprovider;

import java.security.spec.KeySpec;
import java.util.Arrays;

import com.neilalexander.jnacl.crypto.curve25519xsalsa20poly1305;

public class NaclKeySpec implements KeySpec {
    private final byte[] bytes;
    
    NaclKeySpec(byte[] bytes) {
        if (bytes.length != curve25519xsalsa20poly1305.crypto_secretbox_SECRETKEYBYTES) {
            throw new IllegalArgumentException("Only 32 bits/256 bytes size allowed");
        }
        this.bytes = bytes;
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        NaclKeySpec other = (NaclKeySpec) obj;
        if (!Arrays.equals(bytes, other.bytes))
            return false;
        return true;
    }

    /**
     * @return the bytes
     */
    public byte[] getBytes() {
        return bytes;
    }
}
