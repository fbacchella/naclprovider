package fr.loghub.naclprovider;

import java.security.Provider;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class NaclProvider extends Provider {

    public static final String OIDPROPERTY = "fr.loghub.nacl.oid";
    public static final String NAME = "NaCl";
    static final int[] OID;
    static {
        if (System.getProperty(OIDPROPERTY) != null) {
            try {
                OID = Arrays.stream(System.getProperty(OIDPROPERTY).split("\\.")).mapToInt(Integer::parseInt).toArray();
            } catch (NumberFormatException e) {
                throw new ExceptionInInitializerError("Property " + OIDPROPERTY + ": " + System.getProperty(OIDPROPERTY) + " can't be parsed");
            }
        } else {
            OID = new int[] {1, 3, 6, 4, 1, 2}; // private.2, dirty trick
        }
    }

    public static final String OIDSTRING = Arrays.stream(OID).mapToObj(Integer::toString).collect(
            Collectors.joining("."));

    public NaclProvider() {
        super(NAME, 0.1, "A NaCl provider for djb's NaCl library");

        List<String> aliases = Arrays.asList(OIDSTRING, "OID." + OIDSTRING);
        Map<String,String> attributes = Collections.emptyMap();
        putService(new Service(this, "CertificateFactory", NAME, NaclCertificateFactory.class.getCanonicalName(), aliases, attributes));
        putService(new Service(this, "KeyFactory", NAME, NaclKeyFactory.class.getCanonicalName(), aliases, attributes));
        putService(new Service(this, "KeyPairGenerator", NAME, NaclKeyPairGenerator.class.getCanonicalName(), aliases, attributes));
    }

    public static int[] getOid() {
        return OID.clone();
    }

}
