package com.lpaapp.KeyStoreBridge;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.security.KeyStore;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import android.util.Base64;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;


public class KeyStoreBridge {
    private static final String KEYSTORE_PROVIDER = "AndroidKeyStore";
    private static final String ALIAS = "myECKey";
    private static final String EC_CURVE = "secp256r1"; // Example curve
    private static ReactApplicationContext mReactContext;

    IdentityManagerModule(ReactApplicationContext reactContext) {
        super(reactContext);
        mReactContext = reactContext;
    }

    @Override
    public String getName() {
        return "KeyStore"; // Name exposed to React Native
    }

    public void generateAndStoreKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER);

        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                ALIAS,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec(EC_CURVE))
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setUserAuthenticationRequired(true)
                .build();

        kpg.initialize(spec);
        KeyPair keyPair = kpg.generateKeyPair();

        // Substitute the generated keyPair for KMM
    }

    public KeyPair retrieveKeyPair() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
        keyStore.load(null); // Load the keystore
        KeyStore.Entry entry = keyStore.getEntry(ALIAS, null);

        if (entry instanceof KeyStore.PrivateKeyEntry) {
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
            return new KeyPair(privateKeyEntry.getCertificate().getPublicKey(), privateKeyEntry.getPrivateKey());
        }

        return null;
    }

    private KeyPair loadKeyPairFromKMMJar() throws Exception {
      String jarPath = "libs/KMM.jar";  

      // Load the jar
      URLClassLoader classLoader = new URLClassLoader(new URL[]{new File(jarPath).toURI().toURL()});
      Class<?> kmmClass = classLoader.loadClass("org.esimwallet.ECKeyManagement");

      // Assuming your KMMClass has methods to get the keys
      Method getPublicKeyMethod = kmmClass.getMethod("getPublicKey");
      Method getPrivateKeyMethod = kmmClass.getMethod("getPrivateKey");

      PublicKey publicKey = (PublicKey) getPublicKeyMethod.invoke(null); // Assuming static methods
      PrivateKey privateKey = (PrivateKey) getPrivateKeyMethod.invoke(null); 

      return new KeyPair(publicKey, privateKey);
}

}
