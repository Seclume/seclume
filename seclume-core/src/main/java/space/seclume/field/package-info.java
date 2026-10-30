/**
 * Field encryption: column values encrypted in the application with
 * AES-256-GCM-SIV, under data keys that stay in locked native memory.
 *
 * <p>{@link space.seclume.field.FieldKeys} holds the keys,
 * {@link space.seclume.field.EncryptedColumn} encrypts one column, randomized
 * or deterministic. The ciphertext is a binary value any JDBC driver stores.
 */
package space.seclume.field;
