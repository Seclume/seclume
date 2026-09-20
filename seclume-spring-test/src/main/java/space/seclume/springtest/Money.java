package space.seclume.springtest;

import java.math.BigDecimal;

/**
 * A type of the application's own, so that the converter has something to
 * convert. Nothing about it is driver-specific - what is being tested is that
 * a {@code @Converter} reaches the column it writes to.
 */
public record Money(BigDecimal amount, String currency) {

    @Override
    public String toString() {
        return amount.toPlainString() + " " + currency;
    }

    static Money parse(String text) {
        int space = text.lastIndexOf(' ');
        return new Money(new BigDecimal(text.substring(0, space)), text.substring(space + 1));
    }
}
