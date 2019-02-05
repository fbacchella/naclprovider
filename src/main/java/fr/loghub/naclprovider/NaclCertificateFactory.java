package fr.loghub.naclprovider;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
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
                throw new CertificateException("Not enough bytes read");
            }
            ByteBuffer buffer = ByteBuffer.wrap(bytes);
            PublicKeyCodec codec = new PublicKeyCodec(buffer);
            codec.read();
            return new NaclCertificate(codec.getKey());
        } catch (IOException ex) {
            throw new CertificateException("Unreadable NaCl certificate", ex);
        } catch (InvalidKeyException e) {
            throw new CertificateException("Invalid key to import", e);
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
