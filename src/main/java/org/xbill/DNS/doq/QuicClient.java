package org.xbill.DNS.doq;

import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.Message;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.time.Duration;
import net.luminis.quic.QuicClientConnection;
import net.luminis.quic.QuicStream;
import org.xbill.DNS.WireParseException;

@Slf4j
public class QuicClient {

  /** The (ALPN) token for DoQ, see https://www.rfc-editor.org/rfc/rfc9250.html#name-connection-establishment. */
  public static final String DOQ_ALPN = "doq";

  public byte[] sendAndReceive(InetSocketAddress address, Message q, byte[] queryData, Duration timeout) throws Exception {
    QuicClientConnection connection = getQuicClientConnection(address, timeout);
    return sendAndReceive(queryData, connection);
  }

  private QuicClientConnection getQuicClientConnection(InetSocketAddress address, Duration timeout) throws IOException {
    try {
      QuicClientConnection.Builder builder = QuicClientConnection.newBuilder();
      URI uri = new URI("quic://" + address.getAddress().getHostName() + ":" + address.getPort());
      QuicClientConnection connection = builder
        .uri(uri)
        .applicationProtocol(DOQ_ALPN)
        .connectTimeout(timeout)
        .build();

      connection.connect();
      log.debug("Connected to {}", uri);
      return connection;
    }
    catch (URISyntaxException e) {
      // Impossible, just to satisfy the compiler
      throw new IOException(e);
    }
  }

  private byte[] sendAndReceive(byte[] queryData, QuicClientConnection connection) throws IOException {
    // https://www.rfc-editor.org/rfc/rfc9250.html#name-stream-mapping-and-usage:
    // "a 2-octet length field is used in exactly the same way as the 2-octet length field defined for DNS over TCP "
    ByteBuffer buffer = ByteBuffer.allocate(queryData.length + 2);
    buffer.put((byte) (queryData.length >>> 8));
    buffer.put((byte) (queryData.length & 0xFF));
    buffer.put(queryData);
    buffer.flip();

    QuicStream quicStream = connection.createStream(true);
    quicStream.getOutputStream().write(buffer.array(), buffer.arrayOffset(), buffer.limit());
    quicStream.getOutputStream().close();

    InputStream input = quicStream.getInputStream();
    int firstByte = input.read();
    if (firstByte == -1) {
      throw new WireParseException("Incomplete response");
    }
    int secondByte = input.read();
    if (secondByte == -1) {
      throw new WireParseException("Incomplete response");
    }
    int length = (firstByte << 8) + secondByte;
    byte[] data = new byte[length];
    int read = input.read(data);
    input.close();
    if (read == length) {
      return data;
    }
    else {
      throw new WireParseException("Incomplete response");
    }
  }

}
