package fr.loghub.naclprovider;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;

import org.junit.Test;

public class BadKeySizeTest {

    @Test(expected=InvalidKeySpecException.class)
    public void badPrivateKeySpec() throws InvalidKeySpecException {
        new NaclPrivateKeySpec(new byte[] {});
    }

    @Test(expected=InvalidKeyException.class)
    public void badPrivateKey() throws InvalidKeyException {
        new NaclPrivateKey(new byte[] {});
    }

    @Test(expected=InvalidKeySpecException.class)
    public void badPublicKeySpec() throws InvalidKeySpecException {
        new NaclPublicKeySpec(new byte[] {});
    }

    @Test(expected=InvalidKeyException.class)
    public void badPublicKey() throws InvalidKeyException {
        new NaclPublicKey(new byte[] {});
    }

}
