package space.seclume.mongoreactive;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

/** An account, for the reactive repositories. */
@Document("zl_spring_accounts")
public record Account(@Id String id, String owner, long balance) {

    public Account withBalance(long newBalance) {
        return new Account(id, owner, newBalance);
    }
}
