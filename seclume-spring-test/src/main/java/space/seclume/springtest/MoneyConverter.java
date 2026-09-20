package space.seclume.springtest;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

/** {@code @Converter}: one column, one application type. */
@Converter
public class MoneyConverter implements AttributeConverter<Money, String> {

    @Override
    public String convertToDatabaseColumn(Money money) {
        return money == null ? null : money.toString();
    }

    @Override
    public Money convertToEntityAttribute(String text) {
        return text == null ? null : Money.parse(text);
    }
}
