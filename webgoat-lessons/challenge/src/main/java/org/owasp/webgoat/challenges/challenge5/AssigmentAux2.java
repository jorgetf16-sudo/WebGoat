package org.owasp.webgoat.challenges.challenge5;

import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.assignments.AssignmentEndpoint;
import org.owasp.webgoat.assignments.AttackResult;
import org.owasp.webgoat.challenges.Flag;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
@RestController
@Slf4j
public class Assignment5 extends AssignmentEndpoint {

    private final DataSource dataSource;

    public Assignment5(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @PostMapping("/challenge/5")
    @ResponseBody
    public AttackResult login(@RequestParam String username_login, @RequestParam String password_login) throws Exception {
        if (!StringUtils.hasText(username_login) || !StringUtils.hasText(password_login)) {
            return failed(this).feedback("required4").build();
        }
        if (!"Larry".equals(username_login)) {
            return failed(this).feedback("user.not.larry").feedbackArgs(username_login).build();
        }


        try (var connection = dataSource.getConnection()) {
            PreparedStatement statementAux = connection.prepareStatement("select password from challenge_users where userid = '" + "Larry" + "'");
            ResultSet resultSetAux = statementAux.executeQuery();
            String pass=resultSetAux.getNString("password");
            if (pass.equals(password_login)){
                PreparedStatement statement = connection.prepareStatement("select password from challenge_users where userid = '" + "Larry" + "' and password = '" + pass + "'");
                ResultSet resultSet = statement.executeQuery();


                if (resultSet.next()) {
                    return success(this).feedback("challenge.solved").feedbackArgs(Flag.FLAGS.get(5)).build();
                } else {
                    return failed(this).feedback("challenge.close").build();
                }
            }
            else {
                return failed(this).feedback("challenge.close").build();
            }
        }
    }
}

