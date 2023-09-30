package fr.loghub.naclprovider;

import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.cert.Certificate;

import com.neilalexander.jnacl.crypto.curve25519xsalsa20poly1305;

public class NaclCertificate extends Certificate {

    private final NaclPublicKey pk;

    public NaclCertificate(byte[] bytes) throws InvalidKeyException {
        super(NaclProvider.NAME);
        if (bytes.length != curve25519xsalsa20poly1305.crypto_secretbox_PUBLICKEYBYTES) {
            throw new InvalidKeyException("Only 32 bytes/256 bits size allowed, got " + bytes.length + " bytes");
        }
        pk = new NaclPublicKey(bytes);
    }

    public NaclCertificate(PublicKey pk) throws InvalidKeyException {
        super(NaclProvider.NAME);
        if (! NaclProvider.NAME.equals(pk.getAlgorithm())) {
            throw new InvalidKeyException("NaCl key expected, got a " + pk.getAlgorithm());
        }
        this.pk = (NaclPublicKey)pk;
    }

    @Override
    public byte[] getEncoded() {
        return pk.getEncoded();
    }

    @Override
    public void verify(PublicKey key) throws InvalidKeyException {
        if (! pk.equals(key)) {
            throw new InvalidKeyException("Not a matching public key");
        }
    }

    @Override
    public void verify(PublicKey key, String sigProvider)
                    throws InvalidKeyException {
        verify(key);
    }

    @Override
    public String toString() {
        return "NaCl public key/" + pk.hashCode();
    }

    @Override
    public PublicKey getPublicKey() {
        return pk;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = NaclCertificate.class.hashCode();
        result = prime * result + pk.hashCode();
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!super.equals(obj))
            return false;
        if (getClass() != obj.getClass())
            return false;
        NaclCertificate other = (NaclCertificate) obj;
        if (pk == null) {
            return other.pk == null;
        } else
            return pk.equals(other.pk);
    }

}
