package fr.loghub.naclprovider;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.util.Arrays;

import com.neilalexander.jnacl.crypto.curve25519xsalsa20poly1305;

public class NaclPublicKey implements PublicKey {

    private final byte[] bytes;

    NaclPublicKey(NaclPublicKeySpec spec) throws InvalidKeyException {
        this(spec.getBytes());
    }

    NaclPublicKey(byte[] bytes) throws InvalidKeyException {
        if (bytes.length != curve25519xsalsa20poly1305.crypto_secretbox_PUBLICKEYBYTES) {
            throw new InvalidKeyException("Only 32 bytes/256 bits size allowed, got " + bytes.length + " bytes");
        }
        ByteBuffer buffer = ByteBuffer.allocate(curve25519xsalsa20poly1305.crypto_secretbox_PUBLICKEYBYTES + PublicKeyCodec.PUBLICKEYOVERHEAD + NaclProvider.OID.length - 1);
        PublicKeyCodec writer = new PublicKeyCodec(buffer);
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
        return "X.509";
    }

    public byte[] getEncoded() {
        return bytes;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = NaclPublicKey.class.hashCode();
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
        NaclPublicKey other = (NaclPublicKey) obj;
        return Arrays.equals(bytes, other.bytes);
    }

}
