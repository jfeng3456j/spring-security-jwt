package io.springsecurity.springsecurityjwt.controller;


import io.springsecurity.springsecurityjwt.models.AuthenticationRequest;
import io.springsecurity.springsecurityjwt.models.AuthenticationResponse;
import io.springsecurity.springsecurityjwt.services.MyUserDetailsService;
import io.springsecurity.springsecurityjwt.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private MyUserDetailsService userDetailsService;

    @Autowired
    private JwtUtil jwtUtil;

    @RequestMapping({"/jwt"})
    public String jwt() {
         String IAM = "{\n" +
                "    \"Version\": \"2012-10-17\",\n" +
                "    \"Statement\": [\n" +
                "        {\n" +
                "            \"Sid\": \"EnableDisableHongKong\",\n" +
                "            \"Effect\": \"Allow\",\n" +
                "            \"Action\": [\n" +
                "                \"account:EnableRegion\",\n" +
                "                \"account:DisableRegion\"\n" +
                "            ],\n" +
                "            \"Resource\": \"*\",\n" +
                "            \"Condition\": {\n" +
                "                \"StringEquals\": {\"account:TargetRegion\": \"ap-east-1\"}\n" +
                "            }\n" +
                "        },\n" +
                "        {\n" +
                "            \"Sid\": \"ViewConsole\",\n" +
                "            \"Effect\": \"Allow\",\n" +
                "            \"Action\": [\n" +
                "                \"aws-portal:ViewAccount\",\n" +
                "                \"account:ListRegions\"\n" +
                "            ],\n" +
                "            \"Resource\": \"*\"\n" +
                "        }\n" +
                "    ]\n" +
                "}";
        return IAM; }

    @RequestMapping({"/home"})
    public String home() {
        String policy = "{\n" +
                "    \"Version\": \"2012-10-17\",\n" +
                "    \"Statement\": [\n" +
                "        {\n" +
                "            \"Effect\": \"Allow\",\n" +
                "            \"Action\": \"service-prefix:action-name\",\n" +
                "            \"Resource\": \"*\",\n" +
                "            \"Condition\": {\n" +
                "                \"DateGreaterThan\": {\"aws:CurrentTime\": \"2020-04-01T00:00:00Z\"},\n" +
                "                \"DateLessThan\": {\"aws:CurrentTime\": \"2020-06-30T23:59:59Z\"}\n" +
                "            }\n" +
                "        }\n" +
                "    ]\n" +
                "}";
        return policy;
    }


    @RequestMapping(value = "/authenticate", method = RequestMethod.POST)
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {

        try {
            //authenticate user and password
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authenticationRequest.getUserName(),
                            authenticationRequest.getPassword()));
        } catch (BadCredentialsException e) {
            throw new Exception("Incorrect username or password");
        }

        //get the userdetails to generate the token
        final UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUserName());
        String token = jwtUtil.genrateToken(userDetails);

        //pass the token into the response constructor
        return ResponseEntity.ok(new AuthenticationResponse(token));
    }
}
