import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

import java.io.Serializable;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Getter
@ToString
@Builder
public class Person implements Serializable {
    private String firstName;
    private String lastName;
    private String ukFirstName;
    private String ukLastName;
    private String fathersName;
    private Date dateOfBirth;
    private String placeOfBirth;
    private String gender;
    private String nationality;
    private String docNumber;
    private String docDateOExpiry;
    private Date docDateOfIssue;
    private String docIssuingAuthority;

    public static class PersonBuilder {
        public PersonBuilder names(String names) {
            String[] namesArr = names.split("<");
            ukFirstName = getNameByPos(namesArr, 1);
            ukLastName = getNameByPos(namesArr, 0);
            firstName = getNameByPos(namesArr, 4);
            lastName = getNameByPos(namesArr, 3);
            return this;
        }

        public PersonBuilder fathersName(List<String> otherNames) {
            if (otherNames.size() > 0) {
                fathersName = otherNames.get(0);
            }
            return this;
        }

        public PersonBuilder placeOfBirth(List<String> placeOfBirthList) {
            placeOfBirth = placeOfBirthList.stream()
                    .map(String::toString)
                    .collect(Collectors.joining(" "));
            return this;
        }

        private String getNameByPos(String[] namesArr, int pos) {
            return namesArr.length > pos ? namesArr[pos].replaceAll("<", "") : "";
        }
    }
}
