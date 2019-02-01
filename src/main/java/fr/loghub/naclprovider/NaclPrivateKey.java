package fr.loghub.naclprovider;

import java.security.PrivateKey;
import java.util.Arrays;

import com.neilalexander.jnacl.crypto.curve25519xsalsa20poly1305;

public class NaclPrivateKey implements PrivateKey {

    private final byte[] bytes;
    
    public NaclPrivateKey(byte[] bytes) {
        // Overhead is bigger on jks !
        if (bytes.length < curve25519xsalsa20poly1305.crypto_secretbox_SECRETKEYBYTES + PKCS8Codec.PKCS8OVERHEAD) {
            throw new IllegalArgumentException("Only 32 bits/256 bytes size allowed");
        }
        this.bytes = bytes;
    }

    public String getAlgorithm() {
        return NaclProvider.NAME;
    }

    public String getFormat() {
        return "PKCS#8";
    }

    public byte[] getEncoded() {
        return bytes;
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
        NaclPrivateKey other = (NaclPrivateKey) obj;
        if (!Arrays.equals(bytes, other.bytes))
            return false;
        return true;
    }

}
