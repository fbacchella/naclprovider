package fr.loghub.naclprovider;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

import com.neilalexander.jnacl.crypto.curve25519xsalsa20poly1305;

public class NaclPrivateKey implements PrivateKey {

    private final byte[] bytes;

    NaclPrivateKey(PKCS8EncodedKeySpec encoded) throws InvalidKeyException {
        if (encoded.getEncoded().length < PKCS8Codec.PKCS8OVERHEAD + NaclProvider.OID.length - 1) {
            throw new InvalidKeyException("Only 32 bytes/256 bits size allowed, got " + encoded.getEncoded().length + " bytes");
        }
        this.bytes = encoded.getEncoded();
    }

    NaclPrivateKey(byte[] bytes) throws InvalidKeyException {
        if (bytes.length < curve25519xsalsa20poly1305.crypto_secretbox_SECRETKEYBYTES) {
            throw new InvalidKeyException("Only 32 bytes/256 bits size allowed, got " + bytes.length + " bytes");
        }
        ByteBuffer buffer = ByteBuffer.allocate(bytes.length + PKCS8Codec.PKCS8OVERHEAD + NaclProvider.OID.length - 1);
        PKCS8Codec writer = new PKCS8Codec(buffer);
        writer.setKey(bytes);
        writer.setOid(NaclProvider.OID);
        writer.write();
        buffer.flip();
        this.bytes = new byte[buffer.remaining()];
        buffer.get(this.bytes);
    }

    public String getAlgorithm() {
        return NaclProvider.NAME;
    }

    public String getFormat() {
        return "PKCS#8";
    }

    /**
     * Returns the key bytes, encoded but not encrypted according to the PKCS #8 standard.
     *
     * @return the PKCS #8 encoding of the key. Returns a new array
     * each time this method is called.
     */
    public byte[] getEncoded() {
        return Arrays.copyOf(bytes, bytes.length);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = NaclPrivateKey.class.hashCode();
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
        NaclPrivateKey other = (NaclPrivateKey) obj;
        if (bytes.length == other.bytes.length) {
            return Arrays.equals(bytes, other.bytes);
        } else if ((bytes.length == 48 && other.bytes.length == 50) || (bytes.length == 50 && other.bytes.length == 48)) {
            // "JKS" key store modify the private key, needs special comparaison
            byte[] small = (bytes.length == 48) ? bytes : other.bytes;
            byte[] big = (bytes.length == 48) ? other.bytes : bytes;
            boolean match = true;
            for (int i = 0 ; i < 48 ; i++) {
                if (i == 1 || i == 6) {
                    match &= (small[i] + 2) == (big[i]);
                } else if (i == 14) {
                    match &= small[i] + 1 == big[i];
                } else if (i == 15) {
                    match &= big[i] == 0;
                } else if (i == 16) {
                    match &= big[i] == 4;
                } else {
                    match &= small[i] == big[i < 14 ? i : (i + 2)];
                }
            }
            return match;
        } else {
            return false;
        }
    }

}
