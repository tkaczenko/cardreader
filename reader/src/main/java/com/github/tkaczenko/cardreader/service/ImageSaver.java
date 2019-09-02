package com.github.tkaczenko.cardreader.service;

import org.jmrtd.lds.iso19794.FaceImageInfo;
import org.springframework.stereotype.Service;
import org.springframework.validation.annotation.Validated;

import javax.imageio.ImageIO;
import javax.validation.constraints.NotNull;
import java.awt.image.BufferedImage;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * @author Andrii Tkachenko
 */
@Validated
@Service
public class ImageSaver {
    public String saveFaceImage(@NotNull FaceImageInfo imageInfo, String destination) throws IOException {
        String filePath = "%s/%s";

        int imageLength = imageInfo.getImageLength();

        DataInputStream dataInputStream = new DataInputStream(imageInfo.getImageInputStream());
        byte[] buffer = new byte[imageLength];
        dataInputStream.readFully(buffer, 0, imageLength);
        FileOutputStream fileOut2 = new FileOutputStream(String.format(filePath, destination, "tmp.jp2"));
        fileOut2.write(buffer);
        fileOut2.flush();
        fileOut2.close();
        dataInputStream.close();

        File tempFile = new File(String.format(filePath, destination, "tmp.jp2"));
        BufferedImage nImage = ImageIO.read(tempFile);
        if (tempFile.exists()) {
            tempFile.delete();
        }
        File output = new File(String.format(filePath, destination, "facePhoto.jpg"));
        ImageIO.write(nImage, "jpg", output);
        return output.getAbsolutePath();
    }
}
