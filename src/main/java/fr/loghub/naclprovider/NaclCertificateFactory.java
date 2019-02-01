package fr.loghub.naclprovider;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactorySpi;
import java.util.Collection;
import java.util.Collections;

public class NaclCertificateFactory extends CertificateFactorySpi {

    @Override
    public Certificate engineGenerateCertificate(InputStream inStream)
                    throws CertificateException {
        try {
            byte[] bytes = new byte[inStream.available()];
            int read = inStream.read(bytes);
            if (read != bytes.length) {
                throw new CertificateException("Not enough bytes");
            }
            return new NaclCertificate(bytes);
        } catch (IOException ex) {
            throw new CertificateException("Unreadable NaCl certificate", ex);
        }
    }

    @Override
    public Collection<? extends Certificate> engineGenerateCertificates(InputStream inStream)
                    throws CertificateException {
        return Collections.singleton(engineGenerateCertificate(inStream));
    }

    @Override
    public CRL engineGenerateCRL(InputStream inStream) throws CRLException {
        throw new UnsupportedOperationException();
    }

    @Override
    public Collection<? extends CRL> engineGenerateCRLs(InputStream inStream)
                    throws CRLException {
        throw new UnsupportedOperationException();
    }

}
