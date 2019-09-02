package com.github.tkaczenko.cardreader.service;

import com.github.tkaczenko.cardreader.model.Person;
import lombok.RequiredArgsConstructor;
import net.sf.scuba.smartcards.CardServiceException;
import org.jmrtd.PassportService;
import org.jmrtd.lds.LDSFileUtil;
import org.jmrtd.lds.icao.*;
import org.jmrtd.lds.iso19794.FaceImageInfo;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;

/**
 * @author Andrii Tkachenko
 */
@RequiredArgsConstructor
@Service
public class DataReader {
    private static SimpleDateFormat date = new SimpleDateFormat("yyyyMMdd");

    private final PassportService ps;

    public Person read() throws CardServiceException, IOException, ParseException {
        DG1File dg1 = (DG1File) LDSFileUtil.getLDSFile(PassportService.EF_DG1, ps.getInputStream(PassportService.EF_DG1));
        DG11File dg11 = (DG11File) LDSFileUtil.getLDSFile(PassportService.EF_DG11, ps.getInputStream(PassportService.EF_DG11));
        DG12File dg12 = (DG12File) LDSFileUtil.getLDSFile(PassportService.EF_DG12, ps.getInputStream(PassportService.EF_DG12));
        DG2File dg2 = (DG2File) LDSFileUtil.getLDSFile(PassportService.EF_DG2, ps.getInputStream(PassportService.EF_DG2));

        FaceImageInfo faceInfo = dg2.getFaceInfos().stream()
                .flatMap(fi -> fi.getFaceImageInfos().stream())
                .findFirst()
                .orElse(null);

        MRZInfo mrzInfo = dg1.getMRZInfo();
        return Person.builder()
                .names(dg11.getNameOfHolder())
                .fathersName(dg11.getOtherNames())
                .dateOfBirth(date.parse(dg11.getFullDateOfBirth()))
                .placeOfBirth(dg11.getPlaceOfBirth())
                .gender(mrzInfo.getGender().toString())
                .nationality(mrzInfo.getNationality())
                .docNumber(mrzInfo.getDocumentNumber())
                .docDateOExpiry(mrzInfo.getDateOfExpiry())
                .docIssuingAuthority(dg12.getIssuingAuthority())
                .docDateOfIssue(date.parse(dg12.getDateOfIssue()))
                .faceInfo(faceInfo)
                .build();
    }
}
