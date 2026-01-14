package com.example.ssoauth.service;

import com.augur.tacacs.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class TacacsService {

    @org.springframework.beans.factory.annotation.Value("${tacacs.remote-address:localhost}")
    private String tacacsRemoteAddress;

    public boolean authenticate(String host, int port, String secret, String username, String password) {
        TacacsClient client = null;
        try {
            client = new TacacsClient(host, secret); // Port is handled in newSession if standard, or via other
            // constructor?
            // Actually TacacsClient only takes host and secret in constructor.

            // newSession(TAC_PLUS.AUTHEN.SVC svc, String port, String rem_addr, byte
            // priv_lvl)
            // Use configured remote address or default to "localhost" if not set
            String remoteAddr = tacacsRemoteAddress != null && !tacacsRemoteAddress.isEmpty()
                    ? tacacsRemoteAddress
                    : "localhost";

            SessionClient session = client.newSession(TAC_PLUS.AUTHEN.SVC.LOGIN, String.valueOf(port), remoteAddr,
                    TAC_PLUS.PRIV_LVL.USER.code());

            AuthenReply reply = session.authenticate_ASCII(username, password);
            return reply.isOK();

        } catch (Exception e) {
            log.error("TACACS+ Authentication error", e);
            return false;
        } finally {
            if (client != null) {
                client.shutdown();
            }
        }
    }

    public boolean authorize(String host, int port, String secret, String username, String command) {
        TacacsClient client = null;
        try {
            client = new TacacsClient(host, secret);
            // Use configured remote address or default to "localhost" if not set
            String remoteAddr = tacacsRemoteAddress != null && !tacacsRemoteAddress.isEmpty()
                    ? tacacsRemoteAddress
                    : "localhost";

            SessionClient session = client.newSession(TAC_PLUS.AUTHEN.SVC.LOGIN, String.valueOf(port), remoteAddr,
                    TAC_PLUS.PRIV_LVL.USER.code());

            String[] cmdParts = command.split(" ", 2);
            String cmd = cmdParts[0];
            String arg = cmdParts.length > 1 ? cmdParts[1] : "";

            Argument[] args;
            if (arg.isEmpty()) {
                args = new Argument[] { new Argument("service=shell"), new Argument("cmd=" + cmd) };
            } else {
                args = new Argument[] { new Argument("service=shell"), new Argument("cmd=" + cmd),
                        new Argument("cmd-arg=" + arg) };
            }

            // authorize(String username, Argument[] args)
            // We need to specify that the user was authenticated via ASCII
            // authorize(String user, byte authen_method, byte authen_type, byte
            // authen_service, Argument[] args)
            AuthorReply reply = session.authorize(
                    username,
                    TAC_PLUS.AUTHEN.METH.TACACSPLUS,
                    TAC_PLUS.AUTHEN.TYPE.ASCII,
                    TAC_PLUS.AUTHEN.SVC.LOGIN,
                    args);
            return reply.isOK();

        } catch (Exception e) {
            log.error("TACACS+ Authorization error", e);
            return false;
        } finally {
            if (client != null) {
                client.shutdown();
            }
        }
    }
    public boolean account(String host, int port, String secret, String username, String command, int flag) {
        TacacsClient client = null;
        try {
            client = new TacacsClient(host, secret);
            // Use configured remote address or default to "localhost" if not set
            String remoteAddr = tacacsRemoteAddress != null && !tacacsRemoteAddress.isEmpty()
                    ? tacacsRemoteAddress
                    : "localhost";

            SessionClient session = client.newSession(TAC_PLUS.AUTHEN.SVC.LOGIN, String.valueOf(port), remoteAddr,
                    TAC_PLUS.PRIV_LVL.USER.code());

            String[] cmdParts = command.split(" ", 2);
            String cmd = cmdParts[0];
            String arg = cmdParts.length > 1 ? cmdParts[1] : "";
            
            Argument[] args;
            if (arg.isEmpty()) {
                args = new Argument[] { new Argument("service=shell"), new Argument("cmd=" + cmd) };
            } else {
                args = new Argument[] { new Argument("service=shell"), new Argument("cmd=" + cmd),
                        new Argument("cmd-arg=" + arg) };
            }

            // account(byte flags, String user, byte authen_method, byte authen_type, byte authen_service, Argument[] args)
            AcctReply reply = session.account(
                    (byte) flag, // Start, Stop, or Continue
                    username,
                    TAC_PLUS.AUTHEN.METH.TACACSPLUS,
                    TAC_PLUS.AUTHEN.TYPE.ASCII,
                    TAC_PLUS.AUTHEN.SVC.LOGIN,
                    args);

            return reply.isOK();

        } catch (Exception e) {
            log.error("TACACS+ Accounting error", e);
            return false;
        } finally {
            if (client != null) {
                client.shutdown();
            }
        }
    }
}
