package fingerprint.sensor.access.fingerprintsensoraccessdemo;

import android.Manifest;
import android.app.KeyguardManager;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AppCompatActivity;
import android.widget.Toast;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class MainActivity extends AppCompatActivity {

    private static final String KEY_NAME = "FingerPrintKey";

    private Cipher cipher;
    private KeyStore keyStore;
    private KeyGenerator keyGenerator;
    private FingerprintManager.CryptoObject cryptoObject;
    private FingerprintManager fingerprintManager;
    private KeyguardManager keyguardManager;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        if(Build.VERSION.SDK_INT > Build.VERSION_CODES.M)
        {
            //Device has Os version equal or higher than 6.0
            //Gen and Instance of KeyguardManager and FingerPrintManager
            keyguardManager = (KeyguardManager)getSystemService(KEYGUARD_SERVICE);
            fingerprintManager = (FingerprintManager)getSystemService(FINGERPRINT_SERVICE);

            //Check whether device has fingerprint sensor or not
            if(!fingerprintManager.isHardwareDetected())
            {
                Toast.makeText(getBaseContext(), "Your device does not supports Fingerprint Authentication.", Toast.LENGTH_LONG).show();
            }

            //Check whether the user has granted your app the USE_FINGERPRINT permission or not
            if(ActivityCompat.checkSelfPermission(this, Manifest.permission.USE_FINGERPRINT)!= PackageManager.PERMISSION_GRANTED)
            {
                Toast.makeText(getBaseContext(), "Please enable fingerprint permission.", Toast.LENGTH_LONG).show();
            }

            //Check that user has registered at least one fingerprint
            if(!fingerprintManager.hasEnrolledFingerprints())
            {
                Toast.makeText(getBaseContext(), "No fingerprint enrolled. Please register at least one fingerprint.", Toast.LENGTH_LONG).show();
            }

            //Check that the lockscreen is secured
            if(!keyguardManager.isKeyguardSecure())
            {
                Toast.makeText(getBaseContext(), "Please enable lock screen security in your device Settings .", Toast.LENGTH_LONG).show();
            }
            else
            {
                try
                {
                    generateKey();
                }
                catch(Exception e)
                {
                    e.printStackTrace();
                }

                if (initCipher()) {
                    //If the cipher is initialized successfully, then create a CryptoObject instance//
                    cryptoObject = new FingerprintManager.CryptoObject(cipher);

                    // Here, I’m referencing the FingerprintHandler class that we’ll create in the next section. This class will be responsible
                    // for starting the authentication process (via the startAuth method) and processing the authentication process events//
                    FingerprintHandler helper = new FingerprintHandler(this);
                    helper.startAuth(fingerprintManager, cryptoObject);
                }
            }
        }
    }

    private void generateKey() throws Exception
    {
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");

            //Generate Key
            keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");

            //Initialize Empty Keystore
            keyStore.load(null);

            //Initialize KeyGenerator
            keyGenerator.init(new KeyGenParameterSpec.
                            Builder(KEY_NAME, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)//Operations Key Generator is used for
                            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                            .setUserAuthenticationRequired(true)//authentication required to obtain key through fingerprint
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                            .build());

            //Generate the key
            keyGenerator.generateKey();
        } catch (KeyStoreException
                |NoSuchAlgorithmException
                |NoSuchProviderException
                |IOException
                |CertificateException
                |InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    public boolean initCipher()
    {
        try {
            //Obtain a cipher instance and configure it with the properties required for fingerprint authentication//
            cipher = Cipher.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES + "/"
                            + KeyProperties.BLOCK_MODE_CBC + "/"
                            + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        } catch (NoSuchAlgorithmException |
                NoSuchPaddingException e) {
            throw new RuntimeException("Failed to get Cipher", e);
        }

        try {
            keyStore.load(null);
            SecretKey key = (SecretKey) keyStore.getKey(KEY_NAME,null);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            //Return true if the cipher has been initialized successfully//
            return true;
        } catch (KeyPermanentlyInvalidatedException e) {

            //Return false if cipher initialization failed//
            return false;
        } catch (KeyStoreException | CertificateException
                | UnrecoverableKeyException | IOException
                | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Failed to init Cipher", e);
        }
    }

    @Override
    protected void finalize() throws Throwable {

    }
}
