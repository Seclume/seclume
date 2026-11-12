package space.seclume.redis;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;

/**
 * The first handler after the socket - or after seclume's TLS - on the way
 * in: what the server answers passes {@link RespReplyGuard} before Lettuce
 * reads it, so that a password a server gives back in an error is gone
 * before anything makes a {@code String} of the line.
 *
 * <p>The beginning of an error whose end has not arrived is kept here and put
 * in front of the next read; a connection that closes with one kept drops it -
 * half an answer is none.
 */
final class RespReplyHandler extends ChannelInboundHandlerAdapter {

    private final RespReplyGuard guard;
    private ByteBuf held;

    RespReplyHandler(RespReplyGuard guard) {
        this.guard = guard;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (!(msg instanceof ByteBuf read)) {
            ctx.fireChannelRead(msg);
            return;
        }
        ByteBuf in = read;
        if (held != null || read.isReadOnly()) {
            // One buffer of what was kept and what came, and one that can be written to.
            in = ctx.alloc().buffer((held == null ? 0 : held.readableBytes()) + read.readableBytes());
            if (held != null) {
                in.writeBytes(held);
                held.release();
                held = null;
            }
            in.writeBytes(read);
            read.release();
        }
        ByteBuf buffer = in;
        int start = buffer.readerIndex();
        int length = buffer.readableBytes();
        int passed;
        try {
            passed = guard.scan(new RespReplyGuard.Bytes() {
                @Override
                public int length() {
                    return length;
                }

                @Override
                public byte get(int index) {
                    return buffer.getByte(start + index);
                }

                @Override
                public void set(int index, byte value) {
                    buffer.setByte(start + index, value);
                }
            });
        } catch (RuntimeException | Error failure) {
            buffer.release();
            throw failure;
        }
        if (passed == length) {
            ctx.fireChannelRead(buffer);
            return;
        }
        if (passed > 0) {
            ctx.fireChannelRead(buffer.readRetainedSlice(passed));
        }
        held = buffer;
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        drop();
        ctx.fireChannelInactive();
    }

    @Override
    public void handlerRemoved(ChannelHandlerContext ctx) {
        drop();
    }

    private void drop() {
        if (held != null) {
            held.release();
            held = null;
        }
    }
}
