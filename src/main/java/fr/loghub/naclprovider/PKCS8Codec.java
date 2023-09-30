package fr.loghub.naclprovider;

import java.nio.ByteBuffer;

public class PKCS8Codec extends SimpleBerCodec {

    public static final int PKCS8OVERHEAD = 11;

    private int[] oid;
    private byte[] key;

    public PKCS8Codec(ByteBuffer buffer) {
        super(buffer);
    }

    public void write() {
        writeSequence(buffer, i -> {
            writeInteger(i, 0);
            writeSequence(i, j -> writeOid(j, oid));
            writeOctetString(i, key);
        });
    }

    public void read() {
        readSequence(buffer, i -> {
            int version = readInteger(i);
            if (version != 0) {
                throw new IllegalStateException("Only PKCS#8 version 0 supported");
            }
            readSequence(i, j-> oid = readOid(j));
            key = readOctetString(i);
        });
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
