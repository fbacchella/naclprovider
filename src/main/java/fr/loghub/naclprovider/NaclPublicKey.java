package fr.loghub.naclprovider;

import java.security.PublicKey;
import java.util.Arrays;

import com.neilalexander.jnacl.crypto.curve25519xsalsa20poly1305;

public class NaclPublicKey implements PublicKey {

    
    private final byte[] bytes;

    public NaclPublicKey(byte[] bytes) {
        if (bytes.length != (curve25519xsalsa20poly1305.crypto_secretbox_PUBLICKEYBYTES + PublicKeyCodec.PUBLICKEYOVERHEAD)) {
            throw new IllegalArgumentException("Only 32 bytes, got " + bytes.length);
        }
        this.bytes = bytes;
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
