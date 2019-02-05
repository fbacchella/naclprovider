package fr.loghub.naclprovider;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

public class NaclKeyFactory extends KeyFactorySpi {

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec)
                    throws InvalidKeySpecException {
        try {
            if (keySpec instanceof NaclPrivateKeySpec){
                NaclPrivateKeySpec naclspec = (NaclPrivateKeySpec) keySpec;
                return new NaclPublicKey(new NaclPublicKeySpec(naclspec));
            } else if (keySpec instanceof NaclPublicKeySpec){
                NaclPublicKeySpec naclspec = (NaclPublicKeySpec) keySpec;
                return new NaclPublicKey(naclspec.getBytes());
            } else {
                throw new InvalidKeySpecException("keyspec " +  keySpec + " is not a NaCl key");
            }
        } catch (InvalidKeyException e) {
            throw new InvalidKeySpecException("Invalid key spec given", e);
        }
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec)
                    throws InvalidKeySpecException {
        try {
            if (keySpec instanceof NaclPrivateKeySpec){
                NaclPrivateKeySpec naclspec = (NaclPrivateKeySpec) keySpec;
                return new NaclPrivateKey(naclspec.getBytes());
            } else if (keySpec instanceof PKCS8EncodedKeySpec) {
                PKCS8EncodedKeySpec pkcs8spec = (PKCS8EncodedKeySpec) keySpec;
                return new NaclPrivateKey(pkcs8spec);
            } else if (keySpec instanceof NaclPublicKeySpec) {
                throw new IllegalArgumentException("Can't extract private key from public key");
            }  else {
                throw new IllegalArgumentException("Keyspec " +  keySpec + " is not a NaCl compatible key");
            }
        } catch (InvalidKeyException e) {
            throw new InvalidKeySpecException("Invalid key spec given", e);
        }
    }

    @SuppressWarnings("unchecked")
    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpecClass)
                    throws InvalidKeySpecException {
        if (keySpecClass == PKCS8EncodedKeySpec.class && key instanceof NaclPrivateKey) {
            NaclPrivateKey naclkey = (NaclPrivateKey) key;
            return (T) new PKCS8EncodedKeySpec(naclkey.getEncoded());
        } else if (keySpecClass == NaclPrivateKeySpec.class && key instanceof NaclPrivateKey) {
            NaclPrivateKey naclkey = (NaclPrivateKey) key;
            ByteBuffer buffer = ByteBuffer.wrap(naclkey.getEncoded());
            PKCS8Codec reader = new PKCS8Codec(buffer);
            reader.read();
            return (T) new NaclPrivateKeySpec(reader.getKey());
        } else if (keySpecClass == NaclPublicKeySpec.class && key instanceof NaclPublicKey) {
            NaclPublicKey naclkey = (NaclPublicKey) key;
            ByteBuffer buffer = ByteBuffer.wrap(naclkey.getEncoded());
            PublicKeyCodec reader = new PublicKeyCodec(buffer);
            reader.read();
            return (T) new NaclPublicKeySpec(reader.getKey());
        } else if (keySpecClass == NaclPublicKeySpec.class && key instanceof NaclPrivateKey) {
            NaclPrivateKey naclkey = (NaclPrivateKey) key;
            ByteBuffer buffer = ByteBuffer.wrap(naclkey.getEncoded());
            PKCS8Codec reader = new PKCS8Codec(buffer);
            reader.read();
            return (T) new NaclPublicKeySpec(new NaclPrivateKeySpec(reader.getKey()));
        } else if (keySpecClass == NaclPrivateKeySpec.class && key instanceof NaclPublicKey) {
            throw new InvalidKeySpecException("Can't extract private key from public key");
        } else {
            throw new InvalidKeySpecException("Key " +  key + " or keyspec class " + keySpecClass.getName() + " is not NaCl compatible");
        }
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key instanceof NaclPrivateKey || key instanceof NaclPublicKey) {
            return key;
        } else {
            throw new InvalidKeyException("Unsupported key type");
        }
    }

}
