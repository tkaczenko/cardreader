package com.github.tkaczenko.cardreader;

import com.github.tkaczenko.cardreader.model.Person;
import com.github.tkaczenko.cardreader.service.DataConnection;
import com.github.tkaczenko.cardreader.service.DataReader;
import com.github.tkaczenko.cardreader.service.ImageSaver;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.io.File;

/**
 * @author Andrii Tkachenko
 */
@RequiredArgsConstructor
@SpringBootApplication
public class ReadUkrPassportApplication {
    private static final Logger LOGGER = LoggerFactory.getLogger(ReadUkrPassportApplication.class);

    private final DataConnection dataConnection;
    private final DataReader dataReader;
    private final ImageSaver imageSaver;

    public static void main(String[] args) {
        SpringApplication.run(ReadUkrPassportApplication.class, args);
    }

    @Bean
    CommandLineRunner lookup() {
        return args -> {
            // Last 6 digits of Document No.
            String can = args[0];
            if (dataConnection.initConnection(can)) {
                Person person = dataReader.read();
                LOGGER.info("Read data: {}", person);
                String path = imageSaver.saveFaceImage(person.getFaceInfo(), new File(".").getCanonicalPath());
                LOGGER.info("Saved photo image to {}", path);
            } else {
                LOGGER.info("Cannot establish a connection to read data with PACE protocol by CAN key");
            }
        };
    }
}
