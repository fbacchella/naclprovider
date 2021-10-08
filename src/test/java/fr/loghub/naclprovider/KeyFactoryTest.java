package fr.loghub.naclprovider;

import java.lang.reflect.InvocationTargetException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class KeyFactoryTest {

    private static final byte[] PRIVATEKEY = "12346579801234657980132465798012".getBytes();

    @BeforeClass
    public static void register() throws InstantiationException, IllegalAccessException, ClassNotFoundException, IllegalArgumentException, InvocationTargetException, NoSuchMethodException, SecurityException {
        Security.insertProviderAt((Provider) Class.forName("fr.loghub.naclprovider.NaclProvider").getConstructor().newInstance(), Security.getProviders().length + 1);
    }

    @Test
    public void testRead() throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory kf = KeyFactory.getInstance(NaclProvider.NAME);
        NaclPrivateKeySpec privatekey = new NaclPrivateKeySpec(PRIVATEKEY);
        NaclPublicKeySpec publickey = new NaclPublicKeySpec(privatekey);
        PrivateKey pv = kf.generatePrivate(privatekey);
        PublicKey pu = kf.generatePublic(publickey);
        NaclPrivateKeySpec naclspec = kf.getKeySpec(pv, NaclPrivateKeySpec.class);
        PKCS8EncodedKeySpec pkcs8spec = kf.getKeySpec(pv, PKCS8EncodedKeySpec.class);

        Assert.assertEquals("X.509", pu.getFormat());
        Assert.assertEquals("PKCS#8", pv.getFormat());
        Assert.assertArrayEquals(PRIVATEKEY, privatekey.getBytes());
        Assert.assertArrayEquals(PRIVATEKEY, naclspec.getBytes());
        Assert.assertArrayEquals(pv.getEncoded(), pkcs8spec.getEncoded());
    }

}
