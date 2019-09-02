package com.github.tkaczenko.cardreader.service;

import lombok.RequiredArgsConstructor;
import net.sf.scuba.smartcards.CardServiceException;
import org.jmrtd.PACEKeySpec;
import org.jmrtd.PassportService;
import org.jmrtd.lds.CardAccessFile;
import org.jmrtd.lds.PACEInfo;
import org.jmrtd.lds.SecurityInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotNull;
import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author Andrii Tkachenko
 */
@RequiredArgsConstructor
@Validated
@Service
public class DataConnection {
    private static final Logger LOGGER = LoggerFactory.getLogger(DataConnection.class);

    private final PassportService ps;

    public boolean initConnection(@NotNull String can) throws CardServiceException, IOException {
        ps.open();

        CardAccessFile cardAccessFile = new CardAccessFile(ps.getInputStream(PassportService.EF_CARD_ACCESS));
        Collection<SecurityInfo> securityInfos = cardAccessFile.getSecurityInfos();
        SecurityInfo securityInfo = securityInfos.iterator().next();
        LOGGER.info("ProtocolOIDString: " + securityInfo.getProtocolOIDString());
        LOGGER.info("ObjectIdentifier: " + securityInfo.getObjectIdentifier());

        List<PACEInfo> paceInfos = getPACEInfos(securityInfos);
        LOGGER.debug("Found a card access file: paceInfos (" + (paceInfos == null ? 0 : paceInfos.size()) + ") = " + paceInfos);
        if (paceInfos != null && paceInfos.size() > 0) {
            PACEInfo paceInfo = paceInfos.get(0);

            PACEKeySpec paceKey = PACEKeySpec.createCANKey(can);
            ps.doPACE(paceKey, paceInfo.getObjectIdentifier(), PACEInfo.toParameterSpec(paceInfo.getParameterId()), paceInfo.getParameterId());

            ps.sendSelectApplet(true);
            return true;
        } else {
            ps.close();
            return false;
        }
    }

    private List<PACEInfo> getPACEInfos(Collection<SecurityInfo> securityInfos) {
        return securityInfos.stream()
                .filter(securityInfo -> securityInfo instanceof PACEInfo)
                .map(securityInfo -> (PACEInfo) securityInfo)
                .collect(Collectors.toList());
    }
}
