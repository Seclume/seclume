package space.seclume.redis;

import java.nio.ByteBuffer;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;

import space.seclume.internal.SeclumeSslEngine;
import space.seclume.secret.SecretScope;

/**
 * The first handler before the socket on an unencrypted Lettuce connection:
 * a buffer that carries the password's placeholder is written in pieces - the
 * bytes before and after it as they are, and in between the password from
 * native memory, handed to the socket as a direct buffer over that memory and
 * wiped once the socket has taken it. (Encrypted connections do the same in
 * {@link SeclumeSslEngine}.)
 */
final class RespPasswordHandler extends ChannelOutboundHandlerAdapter {

    private final RespPasswordRewriter rewriter;

    RespPasswordHandler(RespPasswordRewriter rewriter) {
        this.rewriter = rewriter;
    }

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise)
            throws Exception {
        if (!(msg instanceof ByteBuf buf) || !buf.isReadable()) {
            ctx.write(msg, promise);
            return;
        }
        ByteBuffer view = buf.nioBuffer(buf.readerIndex(), buf.readableBytes());
        if (!rewriter.contains(view)) {
            ctx.write(msg, promise);
            return;
        }
        java.util.List<Object[]> pieces = new java.util.ArrayList<>();   // {ByteBuf, SecretScope or null}
        int start = view.position();
        try {
            while (view.hasRemaining()) {
                SeclumeSslEngine.Outgoing.Step step = rewriter.next(view);
                if (step.replacement() == null) {
                    pieces.add(new Object[] {buf.retainedSlice(
                            buf.readerIndex() + view.position() - start, step.unchanged()), null});
                    view.position(view.position() + step.unchanged());
                } else {
                    SecretScope secret = step.replacement();
                    pieces.add(new Object[] {Unpooled.wrappedBuffer(secret.segment()
                            .asSlice(0, secret.length()).asByteBuffer()), secret});
                    view.position(view.position() + step.replaced());
                }
            }
        } catch (Exception e) {
            for (Object[] piece : pieces) {
                ((ByteBuf) piece[0]).release();
                if (piece[1] != null) {
                    ((SecretScope) piece[1]).close();
                }
            }
            buf.release();
            promise.setFailure(e);
            return;
        }
        buf.release();
        for (int i = 0; i < pieces.size(); i++) {
            Object[] piece = pieces.get(i);
            ChannelPromise written = i == pieces.size() - 1 ? promise : ctx.newPromise();
            if (piece[1] != null) {
                SecretScope secret = (SecretScope) piece[1];
                written.addListener(done -> secret.close());
            }
            ctx.write(piece[0], written);
        }
    }
}
