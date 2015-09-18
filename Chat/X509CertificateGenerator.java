//
//  X509CertificateGenerator.java
//
//  Modified by : Priyank Patel <pkpatel@cs.stanford.edu>
//                added the policies for the chat rooms A and B
//  Modified by :Murat Ak, Dec 2011
//                  Changed to java.security.cert
package Chat;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.*;
import java.security.*;
import java.math.BigInteger;
//import javax.security.cert.*;
import java.security.cert.*;
import sun.security.x509.*;

public class X509CertificateGenerator {

    public static X509Certificate generateCertificate(
            String subjectName,
            PublicKey subjectPublicKey,
            String issuerName,
            PrivateKey issuerPrivateKey,
            String algorithm,
            boolean allowRoomA,
            boolean allowRoomB) {

        try{
            X509CertInfo info = new X509CertInfo();
            Date from = new Date();
            Date to = new Date(from.getTime() + 365 * 86400000l);
            CertificateValidity interval = new CertificateValidity(from, to);
            BigInteger sn = new BigInteger(64, new SecureRandom());

            info.set(X509CertInfo.VALIDITY, interval);
            info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
            info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(new X500Name(subjectName)));
            info.set(X509CertInfo.ISSUER, new CertificateIssuerName(new X500Name(issuerName)));
            info.set(X509CertInfo.KEY, new CertificateX509Key(subjectPublicKey));
            info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
            
            AlgorithmId algo = new AlgorithmId(AlgorithmId.sha256WithRSAEncryption_oid);
            info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));

            // Sign the cert to identify the algorithm that's used.
            X509CertImpl cert = new X509CertImpl(info);
            cert.sign(issuerPrivateKey, algorithm);

            // Update the algorith, and resign.
            algo = (AlgorithmId)cert.get(X509CertImpl.SIG_ALG);
            info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
            cert = new X509CertImpl(info);
            cert.sign(issuerPrivateKey, algorithm);
            return cert;
        } catch(Exception e){
            e.printStackTrace();
            return null;
        }
    }
}
