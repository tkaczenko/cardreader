package com.github.tkaczenko.cardreader.cfg;

import net.sf.scuba.smartcards.CardService;
import org.jmrtd.PassportService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

/**
 * @author Andrii Tkachenko
 */
@Configuration
public class ReadUkrPassportConfig {
    @Bean
    public CardTerminal cardTerminal() throws CardException {
        return TerminalFactory.getDefault().terminals().list().stream()
                .filter(cardTerminal -> {
                    try {
                        return cardTerminal.isCardPresent();
                    } catch (CardException e) {
                        e.printStackTrace();
                        return false;
                    }
                })
                .findFirst()
                .orElseThrow(RuntimeException::new);
    }

    @Bean
    public CardService cardService(@Qualifier("cardTerminal") CardTerminal cardTerminal) {
        return CardService.getInstance(cardTerminal);
    }

    @Bean
    public PassportService passportService(@Qualifier("cardService") CardService cardService) {
        return new PassportService(cardService, 256, 224, false, true);
    }
}
