package fr.loghub.naclprovider;

import java.io.IOException;
import java.nio.ByteBuffer;

import org.junit.Assert;
import org.junit.Test;

public class PublicKeyCodecTest {

    @Test
    public void testInMemory() {
        ByteBuffer buffer = ByteBuffer.allocate(1024);
        PublicKeyCodec writer = new PublicKeyCodec(buffer);
        writer.setOid(new int[] {1, 2, 122, 121, 120, 119, 118});
        writer.setKey(new byte[] {6, 7, 8, 9});
        writer.write();
        buffer.flip();
        PublicKeyCodec reader = new PublicKeyCodec(buffer);
        reader.read();
        Assert.assertArrayEquals(writer.getKey(), reader.getKey());
        Assert.assertArrayEquals(writer.getOid(), reader.getOid());
    }

}
