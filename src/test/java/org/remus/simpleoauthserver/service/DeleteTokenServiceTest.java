package org.remus.simpleoauthserver.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.remus.simpleoauthserver.repository.PkceIndexRepository;
import org.remus.simpleoauthserver.repository.TokenBinRepository;
import org.springframework.web.servlet.tags.EditorAwareTag;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class DeleteTokenServiceTest {

    @Mock
    private TokenBinRepository tokenBinRepository;

    @Mock
    private PkceIndexRepository pkceIndexRepository;

    @InjectMocks
    private DeleteTokenService testee;



    @Test
    void deleteExpiredTokens() {
        testee.deleteExpiredTokens();

        ArgumentCaptor<Date> captor = ArgumentCaptor.forClass(Date.class);
        verify(tokenBinRepository).deleteOldTokens(captor.capture());
        LocalDateTime value = captor.getValue().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
        LocalDateTime now = LocalDateTime.now();
        assertTrue(value.isBefore(now) && value.isAfter(now.minusSeconds(10)));

        verify(tokenBinRepository).deleteOldTokens(captor.capture());
        value = captor.getValue().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
        assertTrue(value.isBefore(now) && value.isAfter(now.minusSeconds(10)));
    }
}