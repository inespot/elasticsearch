/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.transport.netty4;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.CompositeByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.DefaultHttpContent;
import io.netty.handler.codec.http.DefaultHttpRequest;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpRequestEncoder;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import io.netty.util.AttributeKey;

import org.elasticsearch.action.support.WriteRequest;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.ByteSizeUnit;
import org.elasticsearch.core.TimeValue;
import org.elasticsearch.http.HttpServerTransport;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.test.SecurityIntegTestCase;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.threadpool.ThreadPoolStats;
import org.elasticsearch.xpack.core.security.action.ClearSecurityCacheAction;
import org.elasticsearch.xpack.core.security.action.ClearSecurityCacheRequest;
import org.elasticsearch.xpack.core.security.action.apikey.CreateApiKeyRequestBuilder;
import org.elasticsearch.xpack.security.Security;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.elasticsearch.test.SecuritySettingsSource.ES_TEST_ROOT_USER;
import static org.elasticsearch.test.SecuritySettingsSource.addSSLSettingsForNodePEMFiles;
import static org.elasticsearch.test.SecuritySettingsSourceField.TEST_PASSWORD_SECURE_STRING;
import static org.elasticsearch.test.rest.ESRestTestCase.basicAuthHeaderValue;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;

/// Reproduces the `LEAK: ByteBuf.release() was not called before it's garbage-collected` errors seen on serverless index
/// nodes, where clients abort `_bulk` requests over TLS right after sending the headers and the first few KB of
/// the body (see elastic/incident-management#3261).
///
/// The HTTP header validator (i.e. security authentication) runs asynchronously, and the body chunks decoded in the same
/// socket read as the headers are buffered by `Netty4HttpHeaderValidator` until it completes. The server does not read
/// from the socket while authenticating, but if the client closes the connection straight after sending the request then
/// its TLS `close_notify` is decoded in that same read and the server closes the channel while authentication is still in
/// flight. The buffered chunks must still be released in that case.
public class SecurityNetty4HttpClientAbortDuringAuthenticationIT extends SecurityIntegTestCase {

    private static final int DECLARED_CONTENT_LENGTH = ByteSizeUnit.KB.toIntBytes(150);

    private static final int SENT_CONTENT_LENGTH = 3529;

    @Override
    protected boolean addMockHttpTransport() {
        return false;
    }

    @Override
    protected Settings nodeSettings(int nodeOrdinal, Settings otherSettings) {
        final var builder = Settings.builder().put(super.nodeSettings(nodeOrdinal, otherSettings));
        addSSLSettingsForNodePEMFiles(builder, "xpack.security.http.", randomBoolean());
        return builder.put("xpack.security.http.ssl.enabled", true)
            // lets the test hold API key verification (authentication) in flight
            .put("xpack.security.crypto.thread_pool.size", 1)
            .build();
    }

    public void testClientAbortsBulkRequestWhileAuthenticationInFlight() throws Exception {
        final var nodeName = internalCluster().getRandomNodeName();
        final var httpServerTransport = internalCluster().getInstance(HttpServerTransport.class, nodeName);
        final var threadPool = internalCluster().getInstance(ThreadPool.class, nodeName);

        // an API key missing from the API key auth cache has its hash verified on the security-crypto pool
        // see CachingServiceAccountTokenStore#authenticateWithCache
        final var apiKeyAuthHeader = createApiKeyAuthHeader();
        final var clearCacheResponse = client().execute(
            ClearSecurityCacheAction.INSTANCE,
            new ClearSecurityCacheRequest().cacheName("api_key")
        ).get();
        assertThat(clearCacheResponse.failures(), empty());

        final var bootstrap = newHttpsClient(httpServerTransport);
        try {
            final var serverOpenBefore = httpServerTransport.stats().serverOpen();
            final var channel = bootstrap.connect().sync().channel();
            channel.pipeline().get(SslHandler.class).handshakeFuture().sync();

            final var cryptoThreadBlocked = new CountDownLatch(1);
            final var releaseCryptoThread = new CountDownLatch(1);
            threadPool.executor(Security.SECURITY_CRYPTO_THREAD_POOL_NAME).execute(() -> {
                cryptoThreadBlocked.countDown();
                safeAwait(releaseCryptoThread, TimeValue.timeValueMinutes(1));
            });
            safeAwait(cryptoThreadBlocked);
            try {
                // drop connection mid-body within milliseconds of starting the request
                sendPartialBulkRequest(channel, apiKeyAuthHeader);
                channel.close().sync();

                // the server closes the connection on receipt of close_notify
                assertBusy(() -> assertEquals(serverOpenBefore, httpServerTransport.stats().serverOpen()));
                assertBusy(() -> assertThat(cryptoPoolStats(threadPool).queue(), greaterThanOrEqualTo(1)));
            } finally {
                // authentication completes after the connection has closed
                releaseCryptoThread.countDown();
            }
            assertBusy(() -> {
                final var stats = cryptoPoolStats(threadPool);
                assertEquals(0, stats.queue());
                assertEquals(0, stats.active());
            });
        } finally {
            bootstrap.config().group().shutdownGracefully(0, 0, TimeUnit.SECONDS).sync();
        }

        triggerLeakDetection();
    }

    private String createApiKeyAuthHeader() {
        final var response = new CreateApiKeyRequestBuilder(
            client().filterWithHeader(Map.of("Authorization", basicAuthHeaderValue(ES_TEST_ROOT_USER, TEST_PASSWORD_SECURE_STRING)))
        ).setName(randomIdentifier()).setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE).get();
        final var credentials = response.getId() + ":" + response.getKey();
        return "ApiKey " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }

    /// Sends the headers of a large `_bulk` request followed by only the start of its body. Together with the subsequent
    /// `close_notify` they reach the socket in a single write (see [SingleWriteOnCloseHandler]) so that the server decodes
    /// them all in the same read.
    private static void sendPartialBulkRequest(Channel channel, String authHeader) {
        final var request = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.POST, "/_bulk");
        request.headers().set(HttpHeaderNames.AUTHORIZATION, authHeader);
        request.headers().set(HttpHeaderNames.CONTENT_TYPE, HttpHeaderValues.APPLICATION_JSON);
        request.headers().set(Task.X_OPAQUE_ID_HTTP_HEADER, "aborted-bulk");
        HttpUtil.setContentLength(request, DECLARED_CONTENT_LENGTH);

        final var body = new StringBuilder();
        while (body.length() < SENT_CONTENT_LENGTH) {
            body.append(Strings.format("""
                {"index":{"_index":"test"}}
                {"field":"%s"}
                """, randomAlphaOfLength(between(10, 100))));
        }
        final var sentBody = body.substring(0, SENT_CONTENT_LENGTH).getBytes(StandardCharsets.UTF_8);

        SingleWriteOnCloseHandler.holdWrites(channel);
        channel.write(request);
        channel.writeAndFlush(new DefaultHttpContent(Unpooled.wrappedBuffer(sentBody)));
    }

    private static ThreadPoolStats.Stats cryptoPoolStats(ThreadPool threadPool) {
        for (final var stats : threadPool.stats()) {
            if (stats.name().equals(Security.SECURITY_CRYPTO_THREAD_POOL_NAME)) {
                return stats;
            }
        }
        throw new AssertionError("no stats for thread pool [" + Security.SECURITY_CRYPTO_THREAD_POOL_NAME + "]");
    }

    private static Bootstrap newHttpsClient(HttpServerTransport httpServerTransport) throws Exception {
        final var sslContext = SslContextBuilder.forClient().trustManager(InsecureTrustManagerFactory.INSTANCE).build();
        final var remoteAddress = randomFrom(httpServerTransport.boundAddress().boundAddresses());
        return new Bootstrap().group(new NioEventLoopGroup(1))
            .channel(NioSocketChannel.class)
            .remoteAddress(remoteAddress.getAddress(), remoteAddress.getPort())
            .handler(new ChannelInitializer<SocketChannel>() {
                @Override
                protected void initChannel(SocketChannel ch) {
                    final var pipeline = ch.pipeline();
                    pipeline.addLast(new SingleWriteOnCloseHandler());
                    pipeline.addLast(sslContext.newHandler(ch.alloc()));
                    pipeline.addLast(new HttpRequestEncoder());
                }
            });
    }

    /// Once [#holdWrites] is set, holds back all the bytes written to the socket and writes them in one go when the channel
    /// is closed, so that the request, the start of its body, and the TLS `close_notify` all arrive at the server together.
    private static class SingleWriteOnCloseHandler extends ChannelOutboundHandlerAdapter {

        private static final AttributeKey<Boolean> HOLD_WRITES = AttributeKey.valueOf("hold_writes");

        private CompositeByteBuf heldBytes;

        static void holdWrites(Channel channel) {
            channel.attr(HOLD_WRITES).set(true);
        }

        @Override
        public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) {
            if (ctx.channel().hasAttr(HOLD_WRITES) == false) {
                ctx.write(msg, promise);
                return;
            }
            if (heldBytes == null) {
                heldBytes = ctx.alloc().compositeBuffer();
            }
            heldBytes.addComponent(true, (ByteBuf) msg);
            promise.setSuccess();
        }

        @Override
        public void flush(ChannelHandlerContext ctx) {
            if (ctx.channel().hasAttr(HOLD_WRITES) == false) {
                ctx.flush();
            }
        }

        @Override
        public void close(ChannelHandlerContext ctx, ChannelPromise promise) {
            if (heldBytes != null) {
                ctx.writeAndFlush(heldBytes);
                heldBytes = null;
            }
            ctx.close(promise);
        }
    }

    /// Netty only reports a leak when a tracked buffer is garbage-collected without having been released, and it checks for
    /// such buffers when allocating new ones, so collect garbage and allocate a few times to make any leak visible to
    /// `ESTestCase#checkStaticState` at the end of this test.
    private static void triggerLeakDetection() {
        for (int i = 0; i < 10; i++) {
            System.gc();
            safeSleep(50);
            ByteBufAllocator.DEFAULT.heapBuffer(1).release();
        }
    }
}
