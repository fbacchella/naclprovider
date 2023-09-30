package fr.loghub.naclprovider;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import com.neilalexander.jnacl.crypto.curve25519xsalsa20poly1305;

public class NaclPrivateKeySpec implements KeySpec {
    private final byte[] bytes;

    public NaclPrivateKeySpec(byte[] bytes) throws InvalidKeySpecException {
        if (bytes.length != curve25519xsalsa20poly1305.crypto_secretbox_SECRETKEYBYTES) {
            throw new InvalidKeySpecException("Only 32 bytes/256 bits size allowed, got " + bytes.length + " bytes");
        }
        this.bytes = bytes;
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
        int result = NaclPrivateKeySpec.class.hashCode();
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
        NaclPrivateKeySpec other = (NaclPrivateKeySpec) obj;
        return Arrays.equals(bytes, other.bytes);
    }

}
