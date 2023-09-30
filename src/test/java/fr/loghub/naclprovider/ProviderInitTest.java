package fr.loghub.naclprovider;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

public class ProviderInitTest {

    @BeforeClass
    public static void setProperty() {
        System.setProperty("fr.loghub.nacl.oid", "1.4.5");
    }
    
    @Ignore // Test usefull only a specifc launched URL, used for manual tests
    @Test
    public void testProperty() {
        try {
            Assert.assertEquals("1.4.5", NaclProvider.OIDSTRING);
        } catch (ExceptionInInitializerError e) {
            Assert.assertEquals("Property fr.loghub.nacl.oid: a1.4.5 can't be parsed", e.getMessage());
        }
    }
}
