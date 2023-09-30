package fr.loghub.naclprovider;

import java.nio.ByteBuffer;

import org.junit.Assert;
import org.junit.Test;

public class PKCS8CodecTest {

    @Test
    public void testInMemory() {
        ByteBuffer buffer = ByteBuffer.allocate(1024);
        PKCS8Codec writer = new PKCS8Codec(buffer);
        writer.setOid(new int[] {1, 2, 122, 121, 120, 119, 118});
        writer.setKey(new byte[] {6, 7, 8, 9});
        writer.write();
        buffer.flip();
        PKCS8Codec reader = new PKCS8Codec(buffer);
        reader.read();
        Assert.assertArrayEquals(writer.getKey(), reader.getKey());
        Assert.assertArrayEquals(writer.getOid(), reader.getOid());
    }

}
