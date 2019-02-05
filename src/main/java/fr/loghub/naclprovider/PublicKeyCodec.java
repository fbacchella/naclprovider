package fr.loghub.naclprovider;

import java.nio.ByteBuffer;

public class PublicKeyCodec extends SimpleBerCodec {

    public static final int PUBLICKEYOVERHEAD = 8;

    private byte[] key;
    private int[] oid;

    protected PublicKeyCodec(ByteBuffer buffer) {
        super(buffer);
    }

    @Override
    public void write() {
        writeSequence(buffer, i-> {
            writeSequence(i, j -> {
                writeOid(j, oid);
            });
            writeBitString(i, key);
        });
    }

    @Override
    public void read() {
        readSequence(buffer, i -> {
            readSequence(i, j -> {
                oid = readOid(j);
            });
            key = readBitString(i);
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
