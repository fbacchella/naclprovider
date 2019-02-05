package fr.loghub.naclprovider;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import com.neilalexander.jnacl.crypto.curve25519;
import com.neilalexander.jnacl.crypto.curve25519xsalsa20poly1305;

public class NaclPublicKeySpec implements KeySpec {
    private final byte[] bytes;

    NaclPublicKeySpec(byte[] bytes) throws InvalidKeySpecException {
        if (bytes.length != curve25519xsalsa20poly1305.crypto_secretbox_PUBLICKEYBYTES) {
            throw new InvalidKeySpecException("Only 32 bytes/256 bits size allowed, got " + bytes.length + " bytes");
        }
        this.bytes = bytes;
    }

    /**
     * Derivates the public key from a private key
     * @param spec the private key spec
     */
    public NaclPublicKeySpec(NaclPrivateKeySpec spec) {
        bytes = new byte[curve25519xsalsa20poly1305.crypto_secretbox_PUBLICKEYBYTES];
        curve25519.crypto_scalarmult_base(bytes, spec.getBytes());
    }

    /**
     * @return the bytes
     */
    public byte[] getBytes() {
        return bytes;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = NaclPublicKeySpec.class.hashCode();
        result = prime * result + Arrays.hashCode(bytes);
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        NaclPublicKeySpec other = (NaclPublicKeySpec) obj;
        if (!Arrays.equals(bytes, other.bytes))
            return false;
        return true;
    }

}
