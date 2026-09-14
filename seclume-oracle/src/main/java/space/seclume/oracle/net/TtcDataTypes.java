package space.seclume.oracle.net;

import java.io.IOException;

import space.seclume.internal.WireBuffer;

/**
 * The data-type negotiation of TTC - the second exchange after the ACCEPT.
 *
 * <p>Both sides say here how values are to be represented: which character
 * set, which capabilities, and which of Oracle's several hundred internal
 * types the client understands. Without it the server refuses to go on - an
 * attempt with an empty type list and zeroed capability arrays ends with the
 * connection being closed, without an error packet.
 *
 * <p>The layout, byte for byte:
 *
 * <pre>
 *   1   message type = 2
 *   2   character set, little-endian
 *   2   national character set, little-endian
 *   1   flags
 *   1   length of the compile capabilities, then that many bytes
 *   1   length of the runtime capabilities, then that many bytes
 *   1   a zero byte
 *   n   the type list: four little-endian ub2 per entry
 *   1   a zero byte, the end of the list
 * </pre>
 *
 * <p><b>Where the values come from.</b> Not from guessing: a real handshake of
 * {@code python-oracledb} 4.0.2 (dual-licensed UPL 1.0 / Apache 2.0) against
 * Oracle Free 23ai was recorded and read out field by field. No source code was
 * taken over - the numbers are what goes over the wire, and the wire is the
 * documentation Oracle does not publish. See {@code docs/protocol/oracle.md}.
 *
 * <p>The type table says for every Oracle type which type the client wants it
 * converted into and how it is represented. The pattern is visible in the
 * numbers: the entries below 256 are the classic types, and from 290 upwards
 * every entry maps a new type onto its old equivalent - which is how Oracle
 * has kept the protocol compatible for twenty years.
 */
public final class TtcDataTypes {

    /** Built empty; {@link #negotiate} does the exchange. */
    public TtcDataTypes() {
    }

    /** Oracle's identifier for AL32UTF8 - the character set this driver uses. */
    private static final int CHARSET_AL32UTF8 = 873;
    /** The flag byte between the character sets and the capabilities. */
    private static final int FLAGS = 3;

    private static final int[] COMPILE_CAPABILITIES = {
        0x06, 0x00, 0x00, 0x00, 0xea, 0x18, 0x00, 0x18, 0x01, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x29, 0x90, 0x03, 0x07, 0x03, 0x00, 0x01, 0x00, 0xcf,
        0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x0c, 0x20,
        0x00, 0xb8, 0x00, 0x08, 0x64, 0x00, 0x05, 0x00, 0x3e, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x03
    };

    private static final int[] RUNTIME_CAPABILITIES = {
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00
    };

    private static final int[] TYPES = {
        1, 1, 1, 0, 2, 2, 10, 0, 8, 8, 1, 0,
        12, 12, 10, 0, 23, 23, 1, 0, 24, 24, 1, 0,
        25, 25, 1, 0, 26, 26, 1, 0, 27, 27, 10, 0,
        28, 28, 1, 0, 29, 29, 1, 0, 30, 30, 1, 0,
        31, 31, 1, 0, 32, 32, 1, 0, 33, 33, 1, 0,
        10, 10, 1, 0, 11, 11, 1, 0, 40, 40, 1, 0,
        41, 41, 1, 0, 117, 117, 1, 0, 120, 120, 1, 256,
        290, 34, 1, 256, 291, 35, 1, 256, 292, 36, 1, 256,
        293, 37, 1, 256, 294, 38, 1, 256, 298, 42, 1, 256,
        299, 43, 1, 256, 300, 44, 1, 256, 301, 45, 1, 256,
        302, 46, 1, 256, 303, 47, 1, 256, 304, 48, 1, 256,
        305, 49, 1, 256, 306, 50, 1, 256, 307, 51, 1, 256,
        308, 52, 1, 256, 309, 53, 1, 256, 310, 54, 1, 256,
        311, 55, 1, 256, 312, 56, 1, 256, 313, 57, 1, 256,
        315, 59, 1, 256, 316, 60, 1, 256, 317, 61, 1, 256,
        318, 62, 1, 256, 319, 63, 1, 256, 320, 64, 1, 256,
        321, 65, 1, 256, 322, 66, 1, 256, 323, 67, 1, 256,
        327, 71, 1, 256, 328, 72, 1, 256, 329, 73, 1, 256,
        331, 75, 1, 256, 333, 77, 1, 256, 334, 78, 1, 256,
        335, 79, 1, 256, 336, 80, 1, 256, 337, 81, 1, 256,
        338, 82, 1, 256, 339, 83, 1, 256, 340, 84, 1, 256,
        341, 85, 1, 256, 342, 86, 1, 256, 343, 87, 1, 256,
        344, 88, 1, 256, 345, 89, 1, 256, 346, 90, 1, 256,
        348, 92, 1, 256, 349, 93, 1, 256, 354, 98, 1, 256,
        355, 99, 1, 256, 359, 103, 1, 256, 363, 107, 1, 256,
        380, 124, 1, 256, 381, 125, 1, 256, 382, 126, 1, 256,
        383, 127, 1, 256, 384, 128, 1, 256, 385, 129, 1, 256,
        386, 130, 1, 256, 387, 131, 1, 256, 388, 132, 1, 256,
        389, 133, 1, 256, 390, 134, 1, 256, 391, 135, 1, 256,
        393, 137, 1, 256, 394, 138, 1, 256, 395, 139, 1, 256,
        396, 140, 1, 256, 397, 141, 1, 256, 398, 142, 1, 256,
        399, 143, 1, 256, 400, 144, 1, 256, 401, 145, 1, 256,
        404, 148, 1, 256, 405, 149, 1, 256, 406, 150, 1, 256,
        407, 151, 1, 256, 413, 157, 1, 256, 414, 158, 1, 256,
        415, 159, 1, 256, 416, 160, 1, 256, 417, 161, 1, 256,
        418, 162, 1, 256, 419, 163, 1, 256, 420, 164, 1, 256,
        421, 165, 1, 256, 422, 166, 1, 256, 423, 167, 1, 256,
        424, 168, 1, 256, 425, 169, 1, 256, 426, 170, 1, 256,
        427, 171, 1, 256, 429, 173, 1, 256, 430, 174, 1, 256,
        431, 175, 1, 256, 432, 176, 1, 256, 433, 177, 1, 256,
        449, 193, 1, 256, 450, 194, 1, 256, 454, 198, 1, 256,
        455, 199, 1, 256, 456, 200, 1, 256, 457, 201, 1, 256,
        458, 202, 1, 256, 459, 203, 1, 256, 460, 204, 1, 256,
        461, 205, 1, 256, 462, 206, 1, 256, 463, 207, 1, 256,
        466, 210, 1, 256, 467, 211, 1, 256, 468, 212, 1, 256,
        469, 213, 1, 256, 470, 214, 1, 256, 471, 215, 1, 256,
        472, 216, 1, 256, 473, 217, 1, 256, 474, 218, 1, 256,
        475, 219, 1, 256, 476, 220, 1, 256, 477, 221, 1, 256,
        478, 222, 1, 256, 479, 223, 1, 256, 480, 224, 1, 256,
        481, 225, 1, 256, 482, 226, 1, 256, 483, 227, 1, 256,
        484, 228, 1, 256, 485, 229, 1, 256, 486, 230, 1, 256,
        490, 234, 1, 256, 491, 235, 1, 256, 492, 236, 1, 256,
        493, 237, 1, 256, 494, 238, 1, 256, 495, 239, 1, 256,
        496, 240, 1, 256, 498, 242, 1, 256, 499, 243, 1, 256,
        500, 244, 1, 256, 501, 245, 1, 256, 502, 246, 1, 256,
        509, 253, 1, 256, 510, 254, 1, 512, 513, 1, 1, 512,
        514, 2, 1, 512, 516, 4, 1, 512, 517, 5, 1, 512,
        518, 6, 1, 512, 519, 7, 1, 512, 520, 8, 1, 512,
        521, 9, 1, 512, 522, 10, 1, 512, 523, 11, 1, 512,
        524, 12, 1, 512, 525, 13, 1, 512, 526, 14, 1, 512,
        527, 15, 1, 512, 528, 16, 1, 512, 529, 17, 1, 512,
        530, 18, 1, 512, 531, 19, 1, 512, 532, 20, 1, 512,
        533, 21, 1, 512, 534, 22, 1, 512, 535, 23, 1, 512,
        536, 24, 1, 512, 537, 25, 1, 512, 538, 26, 1, 512,
        539, 27, 1, 512, 540, 28, 1, 512, 541, 29, 1, 512,
        542, 30, 1, 512, 543, 31, 1, 512, 560, 48, 1, 512,
        565, 53, 1, 512, 572, 60, 1, 512, 573, 61, 1, 512,
        574, 62, 1, 512, 575, 63, 1, 512, 576, 64, 1, 512,
        578, 66, 1, 512, 563, 51, 1, 512, 564, 52, 1, 512,
        579, 67, 1, 512, 580, 68, 1, 512, 581, 69, 1, 512,
        582, 70, 1, 512, 583, 71, 1, 512, 584, 72, 1, 512,
        585, 73, 1, 0, 3, 2, 10, 0, 4, 2, 10, 0,
        5, 1, 1, 0, 6, 2, 10, 0, 7, 2, 10, 0,
        9, 1, 1, 0, 15, 1, 1, 0, 39, 39, 1, 0,
        68, 2, 10, 0, 91, 2, 10, 0, 94, 1, 1, 0,
        95, 23, 1, 0, 96, 96, 1, 0, 97, 96, 1, 0,
        100, 100, 1, 0, 101, 101, 1, 0, 102, 102, 1, 0,
        104, 11, 1, 0, 106, 106, 1, 0, 108, 109, 1, 0,
        109, 109, 1, 0, 110, 111, 1, 0, 111, 111, 1, 0,
        112, 112, 1, 0, 113, 113, 1, 0, 114, 114, 1, 0,
        115, 115, 1, 0, 116, 102, 1, 0, 119, 119, 1, 0,
        198, 198, 1, 0, 146, 146, 1, 0, 152, 2, 10, 0,
        153, 2, 10, 0, 154, 2, 10, 0, 155, 1, 1, 0,
        156, 12, 10, 0, 172, 2, 10, 0, 178, 178, 1, 0,
        179, 179, 1, 0, 180, 180, 1, 0, 181, 181, 1, 0,
        182, 182, 1, 0, 183, 183, 1, 0, 184, 12, 10, 0,
        185, 185, 1, 0, 186, 186, 1, 0, 187, 187, 1, 0,
        188, 188, 1, 0, 189, 189, 1, 0, 190, 190, 1, 0,
        195, 112, 1, 0, 196, 113, 1, 0, 197, 114, 1, 0,
        208, 208, 1, 0, 231, 231, 1, 0, 232, 231, 1, 0,
        233, 233, 1, 0, 241, 109, 1, 0, 252, 252, 1, 512,
        590, 78, 1, 512, 591, 79, 1, 512, 592, 80, 1, 512,
        613, 101, 1, 512, 614, 102, 1, 512, 615, 103, 1, 512,
        616, 104, 1, 512, 611, 99, 1, 512, 612, 100, 1, 512,
        593, 81, 1, 512, 594, 82, 1, 512, 595, 83, 1, 512,
        596, 84, 1, 512, 597, 85, 1, 512, 598, 86, 1, 512,
        599, 87, 1, 512, 600, 88, 1, 512, 601, 89, 1, 512,
        602, 90, 1, 512, 603, 91, 1, 512, 604, 92, 1, 512,
        605, 93, 1, 512, 622, 110, 1, 512, 623, 111, 1, 512,
        624, 112, 1, 512, 625, 113, 1, 512, 626, 114, 1, 512,
        627, 115, 1, 512, 628, 116, 1, 512, 629, 117, 1, 512,
        630, 118, 1, 512, 631, 119, 1, 512, 632, 120, 1, 512,
        637, 125, 1, 512, 638, 126, 1, 512, 636, 124, 1, 512,
        639, 127, 1, 512, 663, 151, 1, 512, 640, 128, 1, 512,
        652, 140, 1, 512, 646, 134, 1, 512, 647, 135, 1, 0,
        127, 127, 1, 512, 660, 148, 1, 512, 661, 149, 1, 512,
        665, 153, 1, 512, 669, 157, 1, 512, 670, 158, 1, 0
    };

    /**
     * Sends the type description and reads the answer.
     *
     * <p>The server answers with a data-type message of its own; its content
     * is of no further interest - what matters is that it comes at all,
     * because that is the sign that the description was accepted.
     */
    public void negotiate(NsChannel channel) throws IOException {
        WireBuffer out = channel.beginData();
        putMessage(out);
        channel.sendData();

        int packetType = channel.nextPacket();
        if (packetType != NsPacket.TYPE_DATA) {
            throw new IOException("expected a DATA packet after the type negotiation, got "
                    + NsPacket.typeName(packetType));
        }
        WireBuffer in = channel.packet();
        int messageType = in.getByte() & 0xff;
        if (messageType != TtcMessage.TYPE_DATA_TYPES) {
            throw new IOException("expected a DATA_TYPES message, got "
                    + TtcMessage.typeName(messageType));
        }
    }

    /**
     * Writes the message into a buffer that is already open.
     *
     * <p>Separate from {@link #negotiate} because {@code FAST_AUTH} puts the
     * same bytes into a larger packet - and they have to be the same bytes,
     * not a second version of them.
     */
    static void putMessage(WireBuffer out) {
        out.putByte((byte) TtcMessage.TYPE_DATA_TYPES);
        putShortLe(out, CHARSET_AL32UTF8);
        putShortLe(out, CHARSET_AL32UTF8);
        out.putByte((byte) FLAGS);
        putCapabilities(out, COMPILE_CAPABILITIES);
        putCapabilities(out, RUNTIME_CAPABILITIES);
        out.putByte((byte) 0);
        for (int i = 0; i < TYPES.length; i += 4) {
            putShortLe(out, TYPES[i]);
            putShortLe(out, TYPES[i + 1]);
            putShortLe(out, TYPES[i + 2]);
            putShortLe(out, TYPES[i + 3]);
        }
        out.putByte((byte) 0);                     // end of the list
    }

    /** A capability array: one byte of length, then the bytes. */
    private static void putCapabilities(WireBuffer out, int[] capabilities) {
        out.putByte((byte) capabilities.length);
        for (int value : capabilities) {
            out.putByte((byte) value);
        }
    }

    private static void putShortLe(WireBuffer out, int value) {
        out.putByte((byte) value);
        out.putByte((byte) (value >>> 8));
    }
}
