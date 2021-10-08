package fr.loghub.naclprovider;

import java.lang.reflect.InvocationTargetException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import org.junit.Test;

public class ProviderTest {
    
    @SuppressWarnings("unused")
    @Test
    public void testLoad() throws InstantiationException, IllegalAccessException, ClassNotFoundException, CertificateException, NoSuchAlgorithmException, IllegalArgumentException, InvocationTargetException, NoSuchMethodException, SecurityException {
        System.setProperty("java.security.debug", "all");
        Security.insertProviderAt((Provider) Class.forName("fr.loghub.naclprovider.NaclProvider").getConstructor().newInstance(), Security.getProviders().length + 1);
        Provider nacl = Security.getProvider(NaclProvider.NAME);
        CertificateFactory  cf = CertificateFactory.getInstance(NaclProvider.NAME);
        KeyFactory kf = KeyFactory.getInstance(NaclProvider.NAME);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(NaclProvider.NAME);
    }

}
