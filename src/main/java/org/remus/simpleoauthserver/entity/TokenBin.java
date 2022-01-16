package org.remus.simpleoauthserver.entity;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Index;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import java.util.Date;
import java.util.UUID;

@Entity
@Table(name = "TokenBin", indexes = {@Index(name="Token_INDEX",columnList = "indexHelp,invalidationDate")})
public class TokenBin {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @Column(nullable = false, length = 2048)
    private String token;

    @Column(nullable = false, length = 500)
    private String indexHelp;

    @Column(nullable = false)
    @Temporal(TemporalType.TIMESTAMP)
    private Date invalidationDate;

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
        this.indexHelp = calculateIndex(this.token);
    }

    public Date getInvalidationDate() {
        return invalidationDate;
    }

    public void setInvalidationDate(Date invalidationDate) {
        this.invalidationDate = invalidationDate;
    }

    public String getIndexHelp() {
        return indexHelp;
    }

    public void setIndexHelp(String indexHelp) {
        this.indexHelp = indexHelp;
    }

    public static String calculateIndex(String token) {
        int startIndex = token.length() - Math.min(500, token.length());
        int endIndex = startIndex + Math.min(500, token.length());
        return token.substring(startIndex,endIndex);
    }
}
