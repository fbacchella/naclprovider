# naclprovider

A Provider for use with jnacl

It allows tu use standard Java security code and tools with [jnacl](https://github.com/neilalexander/jnacl), used for example in 
[jeromq](https://github.com/zeromq/jeromq).

For example, private and public keys can be stored in Java's keystore. A main limitation is that, as of today, only JECKS
or JKS works with custom content. PKCS#12 only accesses X.509 certificates associated with a private key.

To use it, either add:

```
security.provider.10=fr.loghub.naclprovider.NaclProvider
```

in `$JRE_HOME/lib/security/java.security` (`$JAVA_HOME/conf/security/java.security` since Java 9).

Or one can add in its startup code:

```
Security.insertProviderAt((Provider) Class.forName("fr.loghub.naclprovider.NaclProvider").newInstance(), Security.getProviders().length + 1);
```

The Algorithm name is "NaCl" for all services, and is defined in `fr.loghub.naclprovider.NaclProvider.NAME`.

To be used in PCKS#8 content, a OID must be defined. The default one is `1.3.6.4.1.2`, but it can be changed with the 
property `fr.loghub.nacl.oid`. It must be used before the first call to any parts of this provider.

Encrypted PCKS#8 is not supported yet, it might be coming.

To use it with a 0MQ socket, the code is:

```
    static {
        Security.insertProviderAt((Provider) Class.forName("fr.loghub.naclprovider.NaclProvider").newInstance(), Security.getProviders().length + 1);
    }

    KeyPairGenerator kg = KeyPairGenerator.getInstance(NaclProvider.NAME);
    KeyPair kp = kg.generateKeyPair();

    PrivateKey prk = kp.getPrivate();
    PublicKey puk = kp.getPublic();
```

Or, with a populated key store:

```
    KeyStore ks = KeyStore.getInstance("...");
    ks.load(new FileInputStream("..."), null);
    PrivateKeyEntry e = (PrivateKeyEntry) ks.getEntry("pair", new KeyStore.PasswordProtection(new char[] {}));
    
    PrivateKey prk = e.getPrivateKey();
    PublicKey puk = e.getCertificate().getPublicKey();
```

And then it can be sent to the socket:

```
    KeyFactory kf = KeyFactory.getInstance(NaclProvider.NAME);
    byte[] privateKey = kf.getKeySpec(prk, NaclPrivateKeySpec.class).getBytes();
    byte[] publicKey = kf.getKeySpec(puk, NaclPublicKeySpec.class).getBytes();
    
    Socket sock = new Socket(...);
    
    sock.setCurveSecretKey(privateKey);
    sock.setCurvePublicKey(publicKey);
```
