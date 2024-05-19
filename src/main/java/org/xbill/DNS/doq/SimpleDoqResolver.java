package org.xbill.DNS.doq;

import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.*;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

/**
 * An implementation of Resolver that sends queries over QUIC (DNS over QUIC, DOQ) as specified in RFC 9250.
 */
@Slf4j
public class SimpleDoqResolver extends SimpleResolver {

  public static final int DEFAULT_DOQ_PORT = 853;
  public static final int DEFAULT_DNS_PORT = DEFAULT_PORT;

  private InetSocketAddress serverAddress;

  public SimpleDoqResolver(SimpleResolver base) throws UnknownHostException {
    if (base.getAddress().getPort() == DEFAULT_DNS_PORT) {
      // https://www.rfc-editor.org/rfc/rfc9250.html#name-port-selection: "DoQ connections MUST NOT use UDP port 53."
      serverAddress = new InetSocketAddress(base.getAddress().getHostName(), DEFAULT_DOQ_PORT);
    } else {
      serverAddress = new InetSocketAddress(base.getAddress().getHostName(), base.getAddress().getPort());
    }
  }

  @Override
  protected CompletableFuture<Message> sendAsync(Message query, boolean forceTcp, Executor executor) {
    // RFC 9250 mandates that the ID field is set to 0, see https://www.rfc-editor.org/rfc/rfc9250.html#name-dns-message-ids
    int qid = 0;
    query.getHeader().setID(qid);

    byte[] queryData = query.toWire(Message.MAXLENGTH);
    if (log.isTraceEnabled()) {
      log.trace(
        "Sending {}/{}, id={} to {}/{}:{}, query:\n{}",
        query.getQuestion().getName(),
        Type.string(query.getQuestion().getType()),
        qid,
        "quic",
        serverAddress.getAddress().getHostAddress(),
        serverAddress.getPort(),
        query);
    } else if (log.isDebugEnabled()) {
      log.debug(
        "Sending {}/{}, id={} to {}/{}:{}",
        query.getQuestion().getName(),
        Type.string(query.getQuestion().getType()),
        qid,
        "quic",
        serverAddress.getAddress().getHostAddress(),
        serverAddress.getPort());
    }

    CompletableFuture<byte[]> result = new CompletableFuture<>();
    executor.execute(() -> {
      try {
        QuicClient quicClient = createOrGetQuicClient();
        result.complete(quicClient.sendAndReceive(serverAddress, query, queryData, getTimeout()));
      } catch (Exception e) {
        log.error("Error sending query", e);
        result.completeExceptionally(e);
      }
    });

    return result.thenComposeAsync(
      in -> {
        CompletableFuture<Message> f = new CompletableFuture<>();

        // Check that the response is long enough.
        if (in.length < Header.LENGTH) {
          f.completeExceptionally(new WireParseException("invalid DNS header - too short"));
          return f;
        }

        Message response;
        try {
          response = parseMessage(in);
        } catch (WireParseException e) {
          f.completeExceptionally(e);
          return f;
        }

        if (response.getQuestion() == null) {
          f.completeExceptionally(
            new WireParseException("invalid message: question section missing"));
          return f;
        }

        // validate name, class and type (rfc5452#section-9.1)
        if (!query.getQuestion().getName().equals(response.getQuestion().getName())) {
          f.completeExceptionally(
            new WireParseException(
              "invalid name in message: expected "
                + query.getQuestion().getName()
                + "; got "
                + response.getQuestion().getName()));
          return f;
        }

        if (query.getQuestion().getDClass() != response.getQuestion().getDClass()) {
          f.completeExceptionally(
            new WireParseException(
              "invalid class in message: expected "
                + DClass.string(query.getQuestion().getDClass())
                + "; got "
                + DClass.string(response.getQuestion().getDClass())));
          return f;
        }

        if (query.getQuestion().getType() != response.getQuestion().getType()) {
          f.completeExceptionally(
            new WireParseException(
              "invalid type in message: expected "
                + Type.string(query.getQuestion().getType())
                + "; got "
                + Type.string(response.getQuestion().getType())));
          return f;
        }

        verifyTSIG(query, response, in);

        response.setResolver(this);
        f.complete(response);
        return f;
      },
      executor);
  }

  private QuicClient createOrGetQuicClient() {
    return new QuicClient();
  }
}
