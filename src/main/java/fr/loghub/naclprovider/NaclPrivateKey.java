package fr.loghub.naclprovider;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

import com.neilalexander.jnacl.crypto.curve25519xsalsa20poly1305;

public class NaclPrivateKey implements PrivateKey {

    private final byte[] bytes;

    public NaclPrivateKey(PKCS8EncodedKeySpec encoded) throws InvalidKeyException {
        if (encoded.getEncoded().length < PKCS8Codec.PKCS8OVERHEAD + NaclProvider.OID.length - 1) {
            throw new InvalidKeyException("Only 32 bytes/256 bits size allowed, got " + encoded.getEncoded().length + " bytes");
        }
        this.bytes = encoded.getEncoded();
    }

    public NaclPrivateKey(byte[] bytes) throws InvalidKeyException {
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

    public byte[] getEncoded() {
        return bytes;
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
        if (!Arrays.equals(bytes, other.bytes))
            return false;
        return true;
    }

}
