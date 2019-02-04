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
        if (keySpec instanceof NaclPrivateKeySpec){
            NaclPrivateKeySpec naclspec = (NaclPrivateKeySpec) keySpec;
            return new NaclPublicKey(naclspec.getBytes());
        } else if (keySpec instanceof NaclPublicKeySpec){
            NaclPublicKeySpec naclspec = (NaclPublicKeySpec) keySpec;

            ByteBuffer buffer = ByteBuffer.allocate(naclspec.getBytes().length + 20);
            PublicKeyCodec writer = new PublicKeyCodec(buffer);
            writer.setKey(naclspec.getBytes());
            writer.setOid(NaclProvider.OID);
            writer.write();
            buffer.flip();
            byte[] encoded= new byte[buffer.remaining()];
            buffer.get(encoded);
            return new NaclPublicKey(encoded);
        } else {
            throw new IllegalArgumentException("keyspec " +  keySpec + " is not a NaCl key");
        }
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec)
                    throws InvalidKeySpecException {
        if (keySpec instanceof PKCS8EncodedKeySpec) {
            PKCS8EncodedKeySpec pks8spec = (PKCS8EncodedKeySpec) keySpec;
            return new NaclPrivateKey(pks8spec.getEncoded());
        } else if (keySpec instanceof NaclPrivateKeySpec){
            NaclPrivateKeySpec naclspec = (NaclPrivateKeySpec) keySpec;

            ByteBuffer buffer = ByteBuffer.allocate(naclspec.getBytes().length + 20);
            PKCS8Codec writer = new PKCS8Codec(buffer);
            writer.setKey(naclspec.getBytes());
            writer.setOid(NaclProvider.OID);
            writer.write();
            buffer.flip();
            byte[] encoded= new byte[buffer.remaining()];
            buffer.get(encoded);
            return new NaclPrivateKey(encoded);
        } else {
            throw new IllegalArgumentException("Keyspec " +  keySpec + " is not a NaCl compatible key");
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
            NaclPrivateKey naclkey = (NaclPrivateKey) key;
            ByteBuffer buffer = ByteBuffer.wrap(naclkey.getEncoded());
            PublicKeyCodec reader = new PublicKeyCodec(buffer);
            reader.read();
            return (T) new NaclPublicKeySpec(reader.getKey());
        } else if (keySpecClass == NaclPrivateKeySpec.class && key instanceof NaclPublicKey) {
            NaclPublicKey naclkey = (NaclPublicKey) key;
            return (T) new NaclPrivateKeySpec(naclkey.getEncoded());
        } else {
            throw new IllegalArgumentException("Key " +  key + " or keyspec class " + keySpecClass.getName() + " is not NaCl compatible");
        }
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        throw new UnsupportedOperationException();
    }

}
