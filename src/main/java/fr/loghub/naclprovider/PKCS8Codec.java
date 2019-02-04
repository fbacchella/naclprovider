package fr.loghub.naclprovider;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class PKCS8Codec extends SimpleBerCodec {

    public static final int PKCS8OVERHEAD = 16;

    private static final byte[] VERSION = new byte[] {INTEGER,1,0};


    private int[] oid;
    private byte[] key;

    public PKCS8Codec(ByteBuffer buffer) {
        super(buffer);
    }

    public void write() {
        writeSequence(buffer, i -> {
            writeInteger(i, 0);
            writeSequence(i, j -> {
                writeOid(j, oid);
            });
            writeOctetString(i, key);
        });
    }

    public void oldwrite() {
        int start = buffer.position();
        buffer.put(SEQUENCE);
        int size1position = buffer.position();
        buffer.put((byte) 0); // place holder for size;
        buffer.put(VERSION);
        // Put EncryptedPrivateKeyInfo
        buffer.put(SEQUENCE);
        buffer.put((byte) (3 + oid.length - 2));
        writeOid(buffer, oid);
        buffer.put(OCTETSTRING);
        buffer.put((byte) key.length);
        buffer.put(key);
        int end = buffer.position();
        buffer.put(size1position, (byte) (end - 2 - start));
    }
    
    public void read() {
        readSequence(buffer, i -> {
            int version = readInteger(i);
            if (version != 0) {
                throw new IllegalStateException("Only version 0 defined");
            }
            readSequence(i, j-> {
                oid = readOid(j);
            });
            key = readOctetString(i);
        });
    }

    public void oldread() {
        boolean valid = buffer.get() == SEQUENCE;
        System.out.format("%d %s\n", 1, valid);
        byte size = buffer.get();
        if (size > buffer.remaining()) {
            throw new IllegalArgumentException("key is not PKCS#8 encoded");
        }
        buffer.limit(size + buffer.position());
        // read version
        byte[] version = new byte[VERSION.length];
        buffer.get(version);
        valid &= Arrays.equals(VERSION, version);
        System.out.format("%d %s\n", 2, valid);
        // EncryptedPrivateKeyInfo SEQUENCE
        valid &= buffer.get() == SEQUENCE;
        System.out.format("%d %s\n", 3, valid);
        byte sequenceLength = buffer.get();
        // OID for algorithm
        ByteBuffer subbuffer = buffer.slice();
        buffer.position(buffer.position() + sequenceLength);
        subbuffer.limit(sequenceLength);
        oid = readOid(subbuffer);
        valid &= oid != null;
        System.out.format("%d %s\n", 4, valid);
        valid &= buffer.get() == OCTETSTRING;
        System.out.format("%d %s\n", 5, valid);
        byte length = buffer.get();
        key = new byte[length];
        buffer.get(key);
        if (! valid) {
            throw new IllegalArgumentException("key is not PKCS#8 encoded");
        }
    }

    public int[] getOid() {
        return oid;
    }

    public void setOid(int[] oid) {
        this.oid = oid;
    }

    public byte[] getKey() {
        return key;
    }

    public void setKey(byte[] key) {
        this.key = key;
    }

}
