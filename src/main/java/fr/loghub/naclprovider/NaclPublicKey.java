package fr.loghub.naclprovider;

import java.security.PublicKey;
import java.util.Arrays;

import com.neilalexander.jnacl.crypto.curve25519;
import com.neilalexander.jnacl.crypto.curve25519xsalsa20poly1305;

public class NaclPublicKey implements PublicKey {

    private final byte[] bytes;

    public NaclPublicKey(byte[] bytes) {
        if (bytes.length != curve25519xsalsa20poly1305.crypto_secretbox_PUBLICKEYBYTES) {
            throw new IllegalArgumentException("Only 32 bytes");
        }
        this.bytes = bytes;
    }

    /**
     * Derivates the public key from a private key
     * @param spec the private key spec
     */
    public NaclPublicKey(NaclKeySpec spec) {
        bytes = new byte[curve25519xsalsa20poly1305.crypto_secretbox_PUBLICKEYBYTES];
        curve25519.crypto_scalarmult_base(bytes, spec.getBytes());
    }

    public String getAlgorithm() {
        return NaclProvider.NAME;
    }

    public String getFormat() {
        return "RAW";
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
        NaclPublicKey other = (NaclPublicKey) obj;
        if (!Arrays.equals(bytes, other.bytes))
            return false;
        return true;
    }

}
