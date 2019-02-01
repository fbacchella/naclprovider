package fr.loghub.naclprovider;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class PKCS8Codec {
    
    public static final int PKCS8OVERHEAD = 16;

    private static final byte INTEGER = 0x02;
    private static final byte OCTETSTRING = 0x04;
    private static final byte OBJECTIDENTIFIER = 0x06;
    private static final byte SEQUENCE = 0x30;
    private static final byte[] VERSION = new byte[] {INTEGER,1,0};

    private final ByteBuffer buffer;

    private int[] oid;
    private byte[] key;

    public PKCS8Codec(ByteBuffer buffer) {
        this.buffer = buffer;
    }

    public void write() {
        int start = buffer.position();
        buffer.put(SEQUENCE);
        int size1position = buffer.position();
        buffer.put((byte) 0); // place holder for size;
        buffer.put(VERSION);
        // Put EncryptedPrivateKeyInfo
        buffer.put(SEQUENCE);
        buffer.put((byte) (3 + oid.length - 2));
        encodeOid();
        buffer.put(OCTETSTRING);
        buffer.put((byte) key.length);
        buffer.put(key);
        int end = buffer.position();
        buffer.put(size1position, (byte) (end - 2 - start));
    }

    private void encodeOid() {
        buffer.put((byte) OBJECTIDENTIFIER);
        buffer.put((byte) (oid.length - 1));
        buffer.put((byte) (oid[0] * 40 + oid[1]));
        for (int i= 2 ; i < oid.length; i++) {
            buffer.put((byte) oid[i]);
        }
    }

    public void read() {
        boolean valid = buffer.get() == SEQUENCE;
        byte size = buffer.get();
        if (size > buffer.remaining()) {
            throw new IllegalArgumentException("key is not PKCS#8 encoded");
        }
        buffer.limit(size + buffer.position());
        // read version
        byte[] version = new byte[VERSION.length];
        buffer.get(version);
        valid &= Arrays.equals(VERSION, version);
        // EncryptedPrivateKeyInfo SEQUENCE
        valid &= buffer.get() == SEQUENCE;
        byte sequenceLength = buffer.get();
        // OID for algorithm
        ByteBuffer subbuffer = buffer.slice();
        buffer.position(buffer.position() + sequenceLength);
        subbuffer.limit(sequenceLength);
        valid &= readOid(subbuffer);
        valid &= buffer.get() == OCTETSTRING;
        byte length = buffer.get();
        key = new byte[length];
        buffer.get(key);
        if (! valid) {
            throw new IllegalArgumentException("key is not PKCS#8 encoded");
        }
    }

    private boolean readOid(ByteBuffer oidBuffer) {
        boolean valid = oidBuffer.get() == OBJECTIDENTIFIER;
        byte[] oidBytes = new byte[oidBuffer.get()];
        oidBuffer.get(oidBytes);
        oid = new int[oidBytes.length + 1];
        oid[1] = oidBytes[0] % 40;
        oid[0] = (oidBytes[0] - oid[1]) / 40;
        for(int i = 1; i < oidBytes.length ; i++) {
            oid[i + 1] = oidBytes[i];
        }
        return valid;
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
