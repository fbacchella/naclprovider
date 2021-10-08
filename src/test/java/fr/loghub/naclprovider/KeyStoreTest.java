package fr.loghub.naclprovider;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class KeyStoreTest {

    private static final char[] password = new char[] {};

    private static final ProtectionParameter protection = new KeyStore.PasswordProtection(password);

    private static KeyFactory NACLKEYFACTORY;
    static {
        try {
            Security.insertProviderAt((Provider) Class.forName("fr.loghub.naclprovider.NaclProvider").getConstructor().newInstance(), Security.getProviders().length + 1);
            NACLKEYFACTORY = KeyFactory.getInstance(NaclProvider.NAME);
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException | NoSuchAlgorithmException | IllegalArgumentException | InvocationTargetException | NoSuchMethodException | SecurityException ex) {
            throw new RuntimeException("NaclProvider unavailable", ex);
        }
    }

    private static byte[] PUBLICKEY;
    private static byte[] PRIVATEKEY;

    @BeforeClass
    public static void createKeys() throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyFactory.getInstance(NaclProvider.NAME).getAlgorithm());
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();
        NaclPublicKeySpec pubkey = NACLKEYFACTORY.getKeySpec(kp.getPublic(), NaclPublicKeySpec.class);
        NaclPrivateKeySpec privateKey = NACLKEYFACTORY.getKeySpec(kp.getPrivate(), NaclPrivateKeySpec.class);
        PUBLICKEY = pubkey.getBytes();
        PRIVATEKEY = privateKey.getBytes();
    }

    @Rule
    public TemporaryFolder testFolder = new TemporaryFolder();

    @Test
    public void TestJks() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableEntryException, InvalidKeySpecException, InvalidKeyException {
        String kspath = Paths.get(testFolder.getRoot().toString(), "naclprovider.jks").toString();
        createKs(kspath, "JKS");
        loadKs(kspath, "JKS");
    }

    @Test
    public void TestJceks() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableEntryException, InvalidKeySpecException, InvalidKeyException {
        String kspath = Paths.get(testFolder.getRoot().toString(), "naclprovider.jceks").toString();
        createKs(kspath, "JCEKS");
        loadKs(kspath, "JCEKS");
    }

    @Test
    public void TestPkcs12() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableEntryException, InvalidKeySpecException, InvalidKeyException {
        String kspath = Paths.get(testFolder.getRoot().toString(), "naclprovider.p12").toString();
        Assert.assertThrows(KeyStoreException.class, () -> {
            try {
                createKs(kspath, "PKCS12");
                loadKs(kspath, "PKCS12");
            } catch (ClassCastException e) {
                // Java 1.8 throws a ClassCastException instead of a KeyStoreException
                throw new KeyStoreException(e.getMessage());
            }
        });
    }

    private void loadKs(String path, String keystoreformat) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, UnrecoverableEntryException, InvalidKeySpecException {
        KeyStore ks = KeyStore.getInstance(keystoreformat);
        ks.load(new FileInputStream(path), null);
        Certificate cert = ks.getCertificate("public");
        Assert.assertNotNull(cert);
        Assert.assertArrayEquals(PUBLICKEY, NACLKEYFACTORY.getKeySpec(cert.getPublicKey(), NaclPublicKeySpec.class).getBytes());

        PrivateKeyEntry e = (PrivateKeyEntry) ks.getEntry("pair", protection);
        Assert.assertTrue(e.getCertificate() instanceof NaclCertificate);
        Assert.assertTrue(e.getPrivateKey() instanceof NaclPrivateKey);
        NaclPublicKeySpec pubkey = NACLKEYFACTORY.getKeySpec(cert.getPublicKey(), NaclPublicKeySpec.class);
        NaclPrivateKeySpec privateKey = NACLKEYFACTORY.getKeySpec(e.getPrivateKey(), NaclPrivateKeySpec.class);
        Assert.assertArrayEquals(PUBLICKEY, pubkey.getBytes());
        Assert.assertArrayEquals(PRIVATEKEY, privateKey.getBytes());
    }

    private void createKs(String path, String keystoreformat) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableEntryException, InvalidKeySpecException, InvalidKeyException {
        KeyStore ks = KeyStore.getInstance(keystoreformat);
        ks.load(null);

        NaclPrivateKeySpec privatekey = new NaclPrivateKeySpec(PRIVATEKEY);
        NaclPublicKeySpec publickey = new NaclPublicKeySpec(PUBLICKEY);

        KeyFactory kf = KeyFactory.getInstance(NaclProvider.NAME);

        NaclCertificate certificate = new NaclCertificate(publickey.getBytes());

        KeyStore.TrustedCertificateEntry tce = new KeyStore.TrustedCertificateEntry(certificate);
        ks.setEntry("public", tce, null);
        ks.setKeyEntry("pair", kf.generatePrivate(privatekey), password, new Certificate[] {certificate});
        try (FileOutputStream os = new FileOutputStream(path)) {
            ks.store(os, password);
        }
    }

}
