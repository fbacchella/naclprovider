package fr.loghub.naclprovider;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Arrays;

import com.neilalexander.jnacl.crypto.curve25519xsalsa20poly1305;

public class NaclCertificate extends Certificate {

    private final byte[] bytes;
    
    protected NaclCertificate(byte[] bytes) {
        super(NaclProvider.NAME);
        if (bytes.length != curve25519xsalsa20poly1305.crypto_secretbox_SECRETKEYBYTES) {
            throw new IllegalArgumentException("Only 32 bits/256 bytes size allowed");
        }
        this.bytes = bytes;
    }

    @Override
    public byte[] getEncoded() throws CertificateEncodingException {
        return bytes;
    }

    @Override
    public void verify(PublicKey key) throws CertificateException,
                    NoSuchAlgorithmException, InvalidKeyException,
                    NoSuchProviderException, SignatureException {

    }

    @Override
    public void verify(PublicKey key, String sigProvider)
                    throws CertificateException, NoSuchAlgorithmException,
                    InvalidKeyException, NoSuchProviderException,
                    SignatureException {
    }

    @Override
    public String toString() {
        return "NaCl public key/" + hashCode();
    }

    @Override
    public PublicKey getPublicKey() {
        return new NaclPublicKey(bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
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
        if (!Arrays.equals(bytes, other.bytes))
            return false;
        return true;
    }

    
}
