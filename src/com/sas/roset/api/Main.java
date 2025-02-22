package com.sas.roset.api;

import java.util.Arrays;

public class Main {
    public static void main(String[] args) {

        System.out.println(

                "============================================================\n" +
                "=  |\\                                                      =\n" +
                "=  | \\                                                     =\n" +
                "=  |  \\                                                    =\n" +
                "=  | / \\ |  Rrrrr    ooooo    ssssss  EEEEEEE  TTTTTTTTTT  =\n" +
                "=  |/__ \\|  R    R  O     O  S        E            tt      =\n" +
                "=  |\\ | /|  Rrrrr   O     O   Sssss   Eeeeee       tt      =\n" +
                "=  | \\ / |  R    R  O     O        S  E            tt      =\n" +
                "=     \\  |  R     R  ooooo   sssssS   EEEEEEE      tt      =\n" +
                "=      \\ |                                                 =\n" +
                "=       \\|            Java API v1.0.0                     =\n" +
                "============================================================\n" +
                        "> SAS-ROSET project is founded and maintained by... \n" +
                        "> Original code for the SAS-ROSET Java API is developed by...\n" +
                        "> SAS-ROS Cipher, SAS-RCS Algorithm, SAS-RBS Algorithm,\n" +
                        "  SAS-DROS Cipher, and SAS-RGM Algorithm used in this API \n  are developed by...\n\n" +
                        "= ...saaiqSAS (Saaiq Abdulla Saeed) [https://saaiqsas.github.io]\n"

        );

        /*
        SAS-ROSET Java API

        +----------------------------------------------+
        | Licensed under The MIT License               |
        | Copyright © 2025-Present Saaiq Abdulla Saeed |
        +----------------------------------------------+

         The SAS-ROSET Java API is the official implementation of the SAS-RCS and SAS-RBS encryption algorithms by saaiqSAS.
         This is a thread-safe static API.

         Usage instructions:
          1. Include the `SAS_ROSET.java` file in your project.
          2. Modify the package to match your project.
          3. Use it as a regular class in your project.
          Feel free to modify the API and its algorithms as needed.

         Official documentation:
         https://sas-roset.github.io/docs/java_api/java_api.html

         See the sampleUsage() method below for example usage:
         */

        boolean debugMode = false; // set to true when debugging or testing

        if (debugMode) {
            debugMode();
        } else {
            usageSample();
        }

    }

    private static void usageSample() {
        // ---------- Generate Keys ----------
        int key_length = 256; /* --> max length is 1,050,000. (too large values are not recommended)
                                     SAS-RBS ONLY support key lengths of two's powers - 2^n (i.e., 128,256,512,1024...)
                                     SAS-RCS can support any key length
                                    ( Longer the key length, greater the keyspace, hence more difficult to brute force )*/

        // int key_length = SAS_ROSET.keyLengthForBits(8); // used to get key length for set bits in two's power - 2^8

        /*
         ---------- DYNAMIC KEY GENERATOR ----------

        Methods:
        - generateDynamicKey()          - Returns key as int[]
        - generateDynamicKeyString()   - Returns key as String

        --- PARAMETERS ---

        RGM_Status_For_Text:
        0: Disabled (unknown characters are kept as is) [NOT RECOMMENDED]      - No forced data increase
        1: Partial  (unknown characters are replaced with known ones via SAS-RGM)   - Partial forced data increase
        2: Full    (all characters, known and unknown, go through SAS-RGM)      - Maximum forced data increase

        RGM_base:
        (How characters/bytes will be represented)
        0: base2   (s2)
        1: base10  (s10)
        2: base16  (s16)
        3: base64  (s64)

        Data_Inc_for_every & Data_Inc_add:
        Data size increase ratio [for_every_N : add_N], where N refers to either characters (SAS-RCS)
        or bytes (SAS-RBS). This controls data size increase by adding random values at specified intervals.
        Data_Inc_for_every range from 0 to 10.
        Data_Inc_add range from 0 to 99.
        0 at either Data_Inc_for_every or Data_Inc_add indicates no data increase.

        random:
        false: Codepoints for the key (charset) are taken in order from the Unicode set, then securely shuffled.
        true: Codepoints for the key (charset) are randomly selected from the Unicode set.

        */

        String Dynamic_Key = SAS_ROSET.generateDynamicKeyString(key_length,1,3,3,2,false,false); // Dynamic Key
        String Static_Key_1 = SAS_ROSET.generateStaticKeyString(key_length); // Static Key
        String Static_Key_2 = SAS_ROSET.generateStaticKeyString(key_length); // Static Key
        String Static_Key_3 = SAS_ROSET.generateStaticKeyString(key_length); // Static Key
        /* Any number of Static Keys can be generated and extracted, and within those some can also be extracted in reverse */


        // ---------- Initializing Space For Key Extraction ----------
        /*
           This step pre-creates arrays to store multiple keys for extraction.
           While not mandatory, it is recommended if multiple Static or Dynamic keys will be extracted,
           as it optimizes memory usage. If not set, the API will auto-expand the arrays,
           which might use more memory.

           In this demonstration, 4 Static Keys will be extracted, so Static Key Stores will be initialized.
           The Dynamic Key Store is not initialized, as only 1 Dynamic Key will be used.
        */

        //SAS_ROSET.initializeDynamicKeyStorage(1, key_length, true, true); initialize arrays related Dynamic Key storage
        SAS_ROSET.initializeStaticKeyStorage(4, key_length);// initialize arrays related Static Key storage


        // ---------- Extract Keys ----------
        /*
           This section extracts keys into memory by storing them in a 2D array.
           There is no limit on the number of keys that can be loaded into memory, as multiple keys may be required
           for different pieces of data. Therefore, when calling any encryption or decryption methods, you must manually
           provide the IDs of all the keys needed to process the specific data.
        */

        int Dynamic_Key_ID = SAS_ROSET.extractDynamicKeyString(Dynamic_Key, false); // ID of the dynamic key
        int Static_Key_1_ID = SAS_ROSET.extractStaticKeyString(Static_Key_1);       // Static key 1
        int Static_Key_2_ID = SAS_ROSET.extractStaticKeyString(Static_Key_2);       // Static key 2
        int Static_Key_3_ID = SAS_ROSET.extractStaticKeyString(Static_Key_3);       // Static key 3

        /*
           A 4th static key is created by reversing Static Key 2's order in memory.
           This method allows the use of more Static Keys without consuming extra storage space on the device.
           The more Static Keys used, the greater the protection against attacks such as frequency analysis.
        */

        int Static_Key_4_ID = SAS_ROSET.extractStaticKeyReversed(Static_Key_2_ID);  // Static key 4 (reversed)


        // Add Static Key IDs to a String[] in order to pass it to other methods
        int[] Static_Key_IDs_Array = {Static_Key_1_ID, Static_Key_2_ID, Static_Key_3_ID, Static_Key_4_ID};

        // printing
        System.out.println("Generated and Extracted Keys\n============================");
        System.out.println("Length of Keys: "+key_length);
        System.out.println("Dynamic Key:  "+ Dynamic_Key);
        System.out.println("Static Key 1: "+ Static_Key_1);
        System.out.println("Static Key 2: "+ Arrays.toString(SAS_ROSET.getStaticKey(Static_Key_2_ID)));
        System.out.println("Static Key 3: "+ Arrays.toString(SAS_ROSET.getStaticKey(Static_Key_3_ID)));
        System.out.println("Static Key 4: "+ Arrays.toString(SAS_ROSET.getStaticKey(Static_Key_4_ID))+"\n");




        // ---------- Set up Quick Processing (Optional) ----------
        /*
           Enabling quick processing reduces search time through key arrays by converting traditional
           primitive arrays into HashMaps, avoiding the need to iterate through the entire array.
           However, it requires more memory and is recommended only when processing large data with long keys.
           (Note: More Static keys do not affect processing time, but longer keys do.)

           IMPORTANT:
           Quick processing is NOT thread-safe when the API is used with multiple key sets.
           If multiple key sets are needed, do not use Quick Processing.

           However, if a single set of keys is used for multithreaded processing of multiple data sets,
           Quick Processing can still work effectively.
        */

        SAS_ROSET.setQuickProcessing(true, Dynamic_Key_ID, Static_Key_IDs_Array);




        // ---------- Encrypt/Decrypt Text Data via SAS-RCS ----------
        String text_data = "Hello how are you doing? I hope you are doing well 😉 !!!";
        String encrypted_text_data = SAS_ROSET.rcsTextEncrypt(Dynamic_Key_ID, Static_Key_IDs_Array, text_data);
        String decrypted_text_data = SAS_ROSET.rcsTextDecrypt(Dynamic_Key_ID, Static_Key_IDs_Array, encrypted_text_data);

        // printing
        System.out.println("Encrypt/Decrypt Text via SAS-RCS\n================================");
        System.out.println("Original Text Data:       "+text_data);
        System.out.println("RCS Encrypted Text Data:  "+encrypted_text_data);
        System.out.println("RCS Decrypted Text Data:  "+decrypted_text_data);

        // ---------- Encrypt/Decrypt Bytes via SAS-RCS ----------
        byte[] byte_data = {(byte) 10,(byte) -2,(byte) 127,(byte) -128,(byte) 82,(byte) 111,(byte) -82,(byte) -107,(byte) 1}; // 9 bytes

        // The method below can be used to get the number of bytes to pass for RCS if a certain text output length is needed
        int maxChars = 1000; // maximum desired text output length
        int maxBytes = SAS_ROSET.rcsNumOfBytesToPass(Dynamic_Key_ID,maxChars);

        String RCS_encrypted_byte_data = SAS_ROSET.rcsByteEncrypt(Dynamic_Key_ID, Static_Key_IDs_Array, byte_data);
        byte[] RCS_decrypted_byte_data = SAS_ROSET.rcsByteDecrypt(Dynamic_Key_ID, Static_Key_IDs_Array, RCS_encrypted_byte_data);
        /*
          Note: when passing byte[] into the encrypt method, do pass them in multiples of 3 if base64 is used for RGM.
          The last set of bytes passed can be an exception.
        */

        // printing
        System.out.println("\nEncrypt/Decrypt Bytes via SAS-RCS (Text Encryption)\n===================================================");
        System.out.println("Bytes needed to Achieve RCS Output Length of "+maxChars+" chars: "+maxBytes);
        System.out.print("Original Byte Data:        ");for (byte eByte:byte_data) { System.out.print(eByte+", ");};System.out.println();
        System.out.println("RCS Encrypted Byte Data:   "+RCS_encrypted_byte_data);
        System.out.print("RCS Decrypted Byte Data:   ");for (byte eByte:RCS_decrypted_byte_data) { System.out.print(eByte+", ");};System.out.println();




        // ---------- Encrypt/Decrypt Bytes via SAS-RBS ----------
        /*
           SAS-RBS supports key lengths that are powers of two (binary powers).
           SAS-RCS supports encryption from 7 bits to 20 bits.

           Use the method below to determine the key length required for a specific bit encryption using SAS-RBS.
           It returns the corresponding key length as an integer.
        */

        int length_for_the_bit = SAS_ROSET.keyLengthForBits(8); // Returns 256 for 8-bit encryption

        /*
           The byte[] provided for SAS-RBS encryption must have a strict length. This length can be
           determined using the method below, which returns the length as an integer. The strict length
           is necessary due to the data increase ratio. Providing an incorrect length may result in errors
           or cause data to be increased by more or less than the expected ratio.

           The strict length differs between encryption and decryption. For example, plain data for encryption
           may need to be provided as 10 bytes, but the encrypted output could be 25 bytes. Thus, when decrypting,
           you must provide 25 bytes. The output byte[] length can be directly calculated using the method below.

           Although byte[] data should generally follow strict lengths, the final segment of data (e.g., the last
           portion of a file) can be an exception. If the data length is smaller than the strict length, no error will
           occur when processing the entire data in one go.

           The method below calculates the strict length for a given Dynamic Key. Be sure to set the decrypt mode
           properly. The maximum byte buffer size must also be provided, and after calculations, the closest
           possible strict length to the max buffer size will be returned.
        */

        int maxByteBufferSize = 32;
        int byteBufferSize_encrypting = SAS_ROSET.rbsNumberOfBytesToPass(Dynamic_Key_ID, maxByteBufferSize, false); // Plain byte[] data size
        int byteBufferSize_decrypting = SAS_ROSET.rbsNumberOfBytesToPass(Dynamic_Key_ID, maxByteBufferSize, true);  // Encrypted byte[] data size


        // Encrypting and Decrypting
        if (SAS_ROSET.keySupportsRBS(Dynamic_Key_ID)) { // Not all keys support RBS (unlike RCS), hence this check is made
            byte[] RBS_encrypted_byte_data = SAS_ROSET.rbsByteEncrypt(Dynamic_Key_ID, Static_Key_IDs_Array, maxByteBufferSize, byte_data);
            byte[] RBS_decrypted_byte_data = SAS_ROSET.rbsByteDecrypt(Dynamic_Key_ID, Static_Key_IDs_Array, maxByteBufferSize, RBS_encrypted_byte_data);

            // printing
            System.out.println("\nEncrypt/Decrypt Bytes via SAS-RBS (Binary Encryption)\n=====================================================");
            System.out.println("Buffer Size (Max): "+maxByteBufferSize+" bytes");
            System.out.println("Buffer Size (Encrypting): "+byteBufferSize_encrypting+" bytes");
            System.out.println("Buffer Size (Decrypting): "+byteBufferSize_decrypting+" bytes");
            System.out.print("Original Byte Data:        ");for (byte eByte:byte_data) { System.out.print(eByte+", ");};System.out.println();
            System.out.print("RBS Encrypted Byte Data:   ");for (byte eByte:RBS_encrypted_byte_data) { System.out.print(eByte+", ");};System.out.println();
            System.out.print("RBS Decrypted Byte Data:   ");for (byte eByte:RBS_decrypted_byte_data) { System.out.print(eByte+", ");};System.out.println();

        }




        // ---------- Secure Metadata Creation ----------
        /*
           The SAS-ROSET API provides 3 methods to help create secure metadata for encrypted data:
             > getCharFromDynamicKey()
             > drosEncrypt()
             > drosDecrypt()

           These methods only require the extraction of a Dynamic Key before use.

           The method below returns a character (as a String) derived from the given Dynamic Key.
           The length of the key will be divided by 'int dividedBy', and 'int add' will be added.
           The 'int add' value can also be negative.

           This method is useful when a single character is needed to represent certain information.
           For example, when using SAS-RCS on Text or Bytes, the output is always text. To distinguish
           whether the encrypted data represents Text or Bytes, a character can be used:
             - (Dyn,2,7) for Text
             - (Dyn,2,6) for Byte

           Even with the same position, the character will differ for different Dynamic Keys, ensuring added security.
        */

        String metaChar = SAS_ROSET.getCharFromDynamicKey(Dynamic_Key_ID,2,8);

        /*
           The following two methods are used to encrypt and decrypt small metadata using only the Dynamic Key
           with the SAS-DROS (Direct Random Object Substitution) Cipher.

           Note: The encryption provided by this method is less secure than SAS-ROS-based SAS-RCS/RBS Algorithms
           and is intended only for creating non-sensitive metadata.
        */

        String metadata = "file.zip";
        String encrypted_metadata = SAS_ROSET.drosEncrypt(Dynamic_Key_ID,metadata);
        String decrypted_metadata = SAS_ROSET.drosDecrypt(Dynamic_Key_ID,encrypted_metadata);

        /*
           The method below retrieves a character from the Unicode set that is not present in the provided data.
           This is useful for generating custom control characters that don't conflict with existing characters in the data.
        */

        String external_char_metadata = SAS_ROSET.getExternalChar(encrypted_metadata);
        String external_char_rcs_enc = SAS_ROSET.getExternalChar(encrypted_text_data);


        // printing
        System.out.println("\nSecure Metadata Creation\n========================");
        System.out.println("Char From Dynamic Key: "+metaChar);
        System.out.println("Original Metadata:  "+metadata);
        System.out.println("Encrypted Metadata: "+encrypted_metadata);
        System.out.println("Decrypted Metadata: "+decrypted_metadata);
        System.out.println("Char Not In Encrypted MetaData: "+external_char_metadata);
        System.out.println("Char Not In Encrypted RCS Text: "+external_char_rcs_enc);

        //while (true) {}
    }


    private static void debugMode() {
        // Test Parameters
        int max_runs = 10;

        int key_length = SAS_ROSET.keyLengthForBits(16); // supplementary characters are present at bit 16 and above
        int RGM_status_for_text = 1;                      // 0: disabled  1: partial  2: full
        int RGM_base = 3;                                 // 0: base2  1: base10  2: base16  3: base64
        int dataInc_for_every = 3;                        // max 9
        int dataInc_add = 2;                              // max 99
        boolean dyn_key_gen_random = false;               /* select the characters randomly through the entire Unicode,
                                                             instead of selecting in an orderly manner and randomly shuffling */
        int num_of_static_keys = 4;
        boolean quick_processing = true;
        int RBS_max_buffer_size = 128;

        // Test Data
        byte[] byte_data = { // All bytes from -128 to 127
                (byte) -128, (byte) -127, (byte) -126, (byte) -125, (byte) -124, (byte) -123, (byte) -122, (byte) -121,
                (byte) -120, (byte) -119, (byte) -118, (byte) -117, (byte) -116, (byte) -115, (byte) -114, (byte) -113,
                (byte) -112, (byte) -111, (byte) -110, (byte) -109, (byte) -108, (byte) -107, (byte) -106, (byte) -105,
                (byte) -104, (byte) -103, (byte) -102, (byte) -101, (byte) -100, (byte) -99, (byte) -98, (byte) -97,
                (byte) -96, (byte) -95, (byte) -94, (byte) -93, (byte) -92, (byte) -91, (byte) -90, (byte) -89,
                (byte) -88, (byte) -87, (byte) -86, (byte) -85, (byte) -84, (byte) -83, (byte) -82, (byte) -81,
                (byte) -80, (byte) -79, (byte) -78, (byte) -77, (byte) -76, (byte) -75, (byte) -74, (byte) -73,
                (byte) -72, (byte) -71, (byte) -70, (byte) -69, (byte) -68, (byte) -67, (byte) -66, (byte) -65,
                (byte) -64, (byte) -63, (byte) -62, (byte) -61, (byte) -60, (byte) -59, (byte) -58, (byte) -57,
                (byte) -56, (byte) -55, (byte) -54, (byte) -53, (byte) -52, (byte) -51, (byte) -50, (byte) -49,
                (byte) -48, (byte) -47, (byte) -46, (byte) -45, (byte) -44, (byte) -43, (byte) -42, (byte) -41,
                (byte) -40, (byte) -39, (byte) -38, (byte) -37, (byte) -36, (byte) -35, (byte) -34, (byte) -33,
                (byte) -32, (byte) -31, (byte) -30, (byte) -29, (byte) -28, (byte) -27, (byte) -26, (byte) -25,
                (byte) -24, (byte) -23, (byte) -22, (byte) -21, (byte) -20, (byte) -19, (byte) -18, (byte) -17,
                (byte) -16, (byte) -15, (byte) -14, (byte) -13, (byte) -12, (byte) -11, (byte) -10, (byte) -9,
                (byte) -8, (byte) -7, (byte) -6, (byte) -5, (byte) -4, (byte) -3, (byte) -2, (byte) -1,
                (byte) 0, (byte) 1, (byte) 2, (byte) 3, (byte) 4, (byte) 5, (byte) 6, (byte) 7,
                (byte) 8, (byte) 9, (byte) 10, (byte) 11, (byte) 12, (byte) 13, (byte) 14, (byte) 15,
                (byte) 16, (byte) 17, (byte) 18, (byte) 19, (byte) 20, (byte) 21, (byte) 22, (byte) 23,
                (byte) 24, (byte) 25, (byte) 26, (byte) 27, (byte) 28, (byte) 29, (byte) 30, (byte) 31,
                (byte) 32, (byte) 33, (byte) 34, (byte) 35, (byte) 36, (byte) 37, (byte) 38, (byte) 39,
                (byte) 40, (byte) 41, (byte) 42, (byte) 43, (byte) 44, (byte) 45, (byte) 46, (byte) 47,
                (byte) 48, (byte) 49, (byte) 50, (byte) 51, (byte) 52, (byte) 53, (byte) 54, (byte) 55,
                (byte) 56, (byte) 57, (byte) 58, (byte) 59, (byte) 60, (byte) 61, (byte) 62, (byte) 63,
                (byte) 64, (byte) 65, (byte) 66, (byte) 67, (byte) 68, (byte) 69, (byte) 70, (byte) 71,
                (byte) 72, (byte) 73, (byte) 74, (byte) 75, (byte) 76, (byte) 77, (byte) 78, (byte) 79,
                (byte) 80, (byte) 81, (byte) 82, (byte) 83, (byte) 84, (byte) 85, (byte) 86, (byte) 87,
                (byte) 88, (byte) 89, (byte) 90, (byte) 91, (byte) 92, (byte) 93, (byte) 94, (byte) 95,
                (byte) 96, (byte) 97, (byte) 98, (byte) 99, (byte) 100, (byte) 101, (byte) 102, (byte) 103,
                (byte) 104, (byte) 105, (byte) 106, (byte) 107, (byte) 108, (byte) 109, (byte) 110, (byte) 111,
                (byte) 112, (byte) 113, (byte) 114, (byte) 115, (byte) 116, (byte) 117, (byte) 118, (byte) 119,
                (byte) 120, (byte) 121, (byte) 122, (byte) 123, (byte) 124, (byte) 125, (byte) 126, (byte) 127
        };

        String text_data = SAS_ROSET.generateDynamicKeyString(SAS_ROSET.keyLengthForBits(16), RGM_status_for_text, RGM_base, dataInc_for_every, dataInc_add, dyn_key_gen_random, false);

        System.out.println("\n========== DEBUG MODE ==========");

        System.out.println("\n========== VERSION ========== ");
        System.out.println("API Version Identifier: " + SAS_ROSET.VERSION_IDENTIFIER);
        System.out.println("API Version: " + SAS_ROSET.API_VERSION);

        System.out.println("\n========== TEST PARAMETERS ========== ");
        System.out.println("max_runs: "+max_runs);
        System.out.println("key_length: "+key_length);
        System.out.println("RGM_status_for_text: "+RGM_status_for_text);
        System.out.println("RGM_base: "+RGM_base);
        System.out.println("dataInc_for_every: "+dataInc_for_every);
        System.out.println("dataInc_add: "+dataInc_add);
        System.out.println("dyn_key_gen_random: "+dyn_key_gen_random);
        System.out.println("num_of_static_keys: "+num_of_static_keys);
        System.out.println("quick_processing: "+quick_processing);
        System.out.println("RBS_max_buffer_size: "+RBS_max_buffer_size);


        for (int i = 1; i <= max_runs; i++) {
            System.out.println("\n========== RUN-" + i + " ==========\n");

            // Generate Keys
            System.out.println("[*] Generating Dynamic Key");
            long s1 = System.currentTimeMillis();
            int[] Dynamic_Key = SAS_ROSET.generateDynamicKey(key_length, RGM_status_for_text, RGM_base, dataInc_for_every, dataInc_add, dyn_key_gen_random);
            long e1 = System.currentTimeMillis();
            System.out.println("[+] Finished Generating Dynamic Key ("+((e1-s1))+"ms)");

            System.out.println("[*] Generating "+num_of_static_keys+" Static Keys");
            int[][] Static_Keys = new int[num_of_static_keys][key_length];
            for (int a = 0; a < num_of_static_keys; a++) {
                long s2 = System.currentTimeMillis();
                Static_Keys[a] = SAS_ROSET.generateStaticKey(key_length);
                long e2 = System.currentTimeMillis();
                System.out.println("[+] Finished Generating Static Key "+a+" ("+((e2-s2))+"ms)");
            }

            // Initialize
            //SAS_ROSET.initializeDynamicKeyStorage(1, key_length, true, true);
            SAS_ROSET.initializeStaticKeyStorage(num_of_static_keys, key_length);

            // Extract Keys
            System.out.println("[*] Extracting Dynamic Key");
            long s3 = System.currentTimeMillis();
            int Dynamic_Key_ID = SAS_ROSET.extractDynamicKey(Dynamic_Key);
            long e3 = System.currentTimeMillis();
            System.out.println("[+] Finished Extracting Dynamic Key ("+((e3-s3))+"ms)");

            System.out.println("[*] Extracting "+num_of_static_keys+" Static Keys");
            int[] Static_Keys_ID = new int[num_of_static_keys];
            for (int b = 0; b < num_of_static_keys; b++) {
                long s4 = System.currentTimeMillis();
                Static_Keys_ID[b] = SAS_ROSET.extractStaticKey(Static_Keys[b]);
                long e4 = System.currentTimeMillis();
                System.out.println("[+] Finished Extracting Static Key "+b+" ("+((e4-s4))+"ms)");
            }

            // Quick Processing
            if (quick_processing) {
                SAS_ROSET.setQuickProcessing(true, Dynamic_Key_ID, Static_Keys_ID);
                System.out.println("[+] Quick Processing Set");
            }

            // RCS Text Encrypt
            System.out.println("[*] Encrypting RCS Text");
            String encrypted_text_data = SAS_ROSET.rcsTextEncrypt(Dynamic_Key_ID, Static_Keys_ID, text_data);
            System.out.println("[*] Decrypting RCS Text");
            String decrypted_text_data = SAS_ROSET.rcsTextDecrypt(Dynamic_Key_ID, Static_Keys_ID, encrypted_text_data);
            if (text_data.equals(decrypted_text_data)) {
                System.out.println("[+] Decrypted RCS Text is same as Original");
            } else {
                System.out.println("[!] Decrypted RCS Text is NOT same as Original !!!");
            }



            // RCS Byte Encrypt
            System.out.println("[*] Encrypting RCS Byte");
            String RCS_encrypted_byte_data = SAS_ROSET.rcsByteEncrypt(Dynamic_Key_ID, Static_Keys_ID, byte_data);
            System.out.println("[*] Decrypting RCS Byte");
            byte[] RCS_decrypted_byte_data = SAS_ROSET.rcsByteDecrypt(Dynamic_Key_ID, Static_Keys_ID, RCS_encrypted_byte_data);

            boolean RCS_byte_same = true;
            for (int c = 0; c < RCS_decrypted_byte_data.length; c++) {
                if (byte_data[c] != RCS_decrypted_byte_data[c]) {
                    RCS_byte_same = false;
                    break;
                }
            }
            if (RCS_byte_same) {
                System.out.println("[+] Decrypted RCS Byte is same as Original");
            } else {
                System.out.println("[!] Decrypted RCS Byte is NOT same as Original !!!");
            }

            // RBS Byte Encrypt
            if (SAS_ROSET.keySupportsRBS(Dynamic_Key_ID)) { // Not all keys support RBS (unlike RCS), hence this check is made
                System.out.println("[*] Encrypting RBS Byte");
                byte[] RBS_encrypted_byte_data = SAS_ROSET.rbsByteEncrypt(Dynamic_Key_ID, Static_Keys_ID, RBS_max_buffer_size, byte_data);
                System.out.println("[*] Decrypting RBS Byte");
                byte[] RBS_decrypted_byte_data = SAS_ROSET.rbsByteDecrypt(Dynamic_Key_ID, Static_Keys_ID, RBS_max_buffer_size, RBS_encrypted_byte_data);

                boolean RBS_byte_same = true;
                for (int c = 0; c < RBS_decrypted_byte_data.length; c++) {
                    if (byte_data[c] != RBS_decrypted_byte_data[c]) {
                        RBS_byte_same = false;
                        break;
                    }
                }
                if (RBS_byte_same) {
                    System.out.println("[+] Decrypted RBS Byte is same as Original");
                } else {
                    System.out.println("[!] Decrypted RBS Byte is NOT same as Original !!!");
                }
            } else {
                System.out.println("[?] Key Does Not Support RBS");
            }


        }
        System.out.println("\n========== Finished All Runs ==========");
    }
}