package fr.loghub.naclprovider;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;

import com.neilalexander.jnacl.crypto.curve25519;
import com.neilalexander.jnacl.crypto.curve25519xsalsa20poly1305;

public class NaclKeyPairGenerator extends KeyPairGeneratorSpi {

    SecureRandom random = null;

    @Override
    public void initialize(int keysize, SecureRandom random) {
        if (keysize != curve25519xsalsa20poly1305.crypto_secretbox_SECRETKEYBYTES * 8) {
            throw new IllegalArgumentException("Only 32 bits/256 bytes size allowed");
        }
        this.random = random;
    }

    @Override
    public KeyPair generateKeyPair() {
        if (random == null) {
            throw new IllegalStateException("Not initialized");
        }
        byte[] sk = new byte[curve25519xsalsa20poly1305.crypto_secretbox_SECRETKEYBYTES];
        byte[] pk = new byte[curve25519xsalsa20poly1305.crypto_secretbox_PUBLICKEYBYTES];
        random.nextBytes(sk);
        curve25519.crypto_scalarmult_base(pk, sk);

        try {
            return new KeyPair(new NaclPublicKey(pk), new NaclPrivateKey(sk));
        } catch (InvalidKeyException e) {
            throw new IllegalStateException("Impossible state", e);
        }
    }

}
