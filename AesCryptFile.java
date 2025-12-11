import javax.crypto.*;
        import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
        import java.nio.file.*;
        import java.security.*;
        import java.util.Base64;
import java.util.Scanner;

public class AesCryptFile {

    private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int AES_KEY_BITS = 128;
    private static final int IV_LENGTH_BYTES = 16;
    private static final String CIPHERTEXT_FILENAME = "ciphertext.txt";
    private static final String PLAINTEXT_FILENAME = "plaintext.txt";

    private final Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) {
        AesCryptFile app = new AesCryptFile();
        app.runMenu();
    }

    private void runMenu() {
        boolean done = false;
        while (!done) {
            printMenu();
            System.out.print("Enter option: ");
            String choice = scanner.nextLine().trim();

            switch (choice) {
                case "1":
                    encryptFlow();
                    break;
                case "2":
                    decryptFlow();
                    break;
                case "3":
                    System.out.println("Quitting application. Goodbye.");
                    done = true;
                    break;
                default:
                    System.out.println("Invalid option. Please enter 1, 2 or 3.\n");
            }
        }
    }

    private void printMenu() {
        System.out.println("=== AES File Encrypt / Decrypt ===");
        System.out.println("1. Encrypt a File");
        System.out.println("2. Decrypt a File");
        System.out.println("3. Quit");
    }

    private void encryptFlow() {
        try {
            System.out.print("Enter filename to encrypt: ");
            String filename = scanner.nextLine().trim();

            if (filename.isEmpty()) {
                System.out.println("Filename cannot be empty.");
                return;
            }

            Path sourcePath = Paths.get(filename);
            if (!Files.exists(sourcePath) || Files.isDirectory(sourcePath)) {
                System.out.println("File not found or is a directory: " + filename);
                return;
            }

            byte[] plaintext = Files.readAllBytes(sourcePath);

            SecretKey key = generateRandomKey();
            byte[] iv = generateRandomIv();

            byte[] ciphertext = encrypt(plaintext, key, iv);

            // Write IV + ciphertext in Base64 to ciphertext.txt
            byte[] ivPlusCipher = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, ivPlusCipher, 0, iv.length);
            System.arraycopy(ciphertext, 0, ivPlusCipher, iv.length, ciphertext.length);

            String base64Out = Base64.getEncoder().encodeToString(ivPlusCipher);

            Files.write(Paths.get(CIPHERTEXT_FILENAME), base64Out.getBytes());

            // Print key to screen (Base64)
            String keyBase64 = Base64.getEncoder().encodeToString(key.getEncoded());

            System.out.println("\nFile encrypted successfully.");
            System.out.println("Encrypted data written to: " + CIPHERTEXT_FILENAME);
            System.out.println("Encryption key (BASE64) -- store this safely. You will need it to decrypt:");
            System.out.println(keyBase64 + "\n");

        } catch (IOException e) {
            System.out.println("I/O error during encryption: " + e.getMessage());
        } catch (GeneralSecurityException e) {
            System.out.println("Encryption error: " + e.getMessage());
        } catch (Exception e) {
            System.out.println("Unexpected error during encryption: " + e.getMessage());
        }
    }

    private void decryptFlow() {
        try {
            System.out.print("Enter filename to decrypt (e.g., " + CIPHERTEXT_FILENAME + "): ");
            String filename = scanner.nextLine().trim();

            if (filename.isEmpty()) {
                System.out.println("Filename cannot be empty.");
                return;
            }

            Path cipherPath = Paths.get(filename);
            if (!Files.exists(cipherPath) || Files.isDirectory(cipherPath)) {
                System.out.println("File not found or is a directory: " + filename);
                return;
            }

            System.out.print("Enter key (BASE64): ");
            String keyBase64 = scanner.nextLine().trim();

            if (keyBase64.isEmpty()) {
                System.out.println("Key cannot be empty.");
                return;
            }

            byte[] keyBytes;
            try {
                keyBytes = Base64.getDecoder().decode(keyBase64);
            } catch (IllegalArgumentException ex) {
                System.out.println("Key is not valid Base64.");
                return;
            }

            if (keyBytes.length != AES_KEY_BITS / 8) {
                System.out.printf("Invalid key length: expected %d bytes (Base64 for %d-bit key), got %d bytes.%n",
                        AES_KEY_BITS / 8, AES_KEY_BITS, keyBytes.length);
                return;
            }

            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");

            // Read Base64 content and split IV + ciphertext
            String base64Content = new String(Files.readAllBytes(cipherPath)).trim();
            if (base64Content.isEmpty()) {
                System.out.println("Ciphertext file is empty.");
                return;
            }

            byte[] ivPlusCipher;
            try {
                ivPlusCipher = Base64.getDecoder().decode(base64Content);
            } catch (IllegalArgumentException ex) {
                System.out.println("Ciphertext file does not contain valid Base64 data.");
                return;
            }

            if (ivPlusCipher.length < IV_LENGTH_BYTES + 1) {
                System.out.println("Ciphertext data is too short or corrupted.");
                return;
            }

            byte[] iv = new byte[IV_LENGTH_BYTES];
            byte[] ciphertext = new byte[ivPlusCipher.length - IV_LENGTH_BYTES];
            System.arraycopy(ivPlusCipher, 0, iv, 0, IV_LENGTH_BYTES);
            System.arraycopy(ivPlusCipher, IV_LENGTH_BYTES, ciphertext, 0, ciphertext.length);

            byte[] plaintext;
            try {
                plaintext = decrypt(ciphertext, keySpec, iv);
            } catch (BadPaddingException e) {
                System.out.println("Decryption failed: likely an invalid key or corrupted ciphertext.");
                return;
            }

            Files.write(Paths.get(PLAINTEXT_FILENAME), plaintext);
            System.out.println("\nFile decrypted successfully.");
            System.out.println("Decrypted plaintext written to: " + PLAINTEXT_FILENAME + "\n");
        } catch (IOException e) {
            System.out.println("I/O error during decryption: " + e.getMessage());
        } catch (GeneralSecurityException e) {
            System.out.println("Decryption error: " + e.getMessage());
        } catch (Exception e) {
            System.out.println("Unexpected error during decryption: " + e.getMessage());
        }
    }

    private SecretKey generateRandomKey() throws NoSuchAlgorithmException {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(AES_KEY_BITS, SecureRandom.getInstanceStrong());
        return kg.generateKey();
    }

    private byte[] generateRandomIv() {
        byte[] iv = new byte[IV_LENGTH_BYTES];
        SecureRandom rng;
        try {
            rng = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            rng = new SecureRandom(); // fallback
        }
        rng.nextBytes(iv);
        return iv;
    }

    private byte[] encrypt(byte[] data, SecretKey key, byte[] iv) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

    private byte[] decrypt(byte[] ciphertext, Key key, byte[] iv) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(ciphertext);
    }
}

