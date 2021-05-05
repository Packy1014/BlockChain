package com.packy.btc;

import com.google.common.primitives.Bytes;
import org.bitcoinj.core.Base58;
import org.bitcoinj.core.ECKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.util.Arrays;

public class BTCAddressGenerator {

    /**
     * Output: Sample Bitcoin Address Generation steps starting from 0 to 9 - Step 5 and 6 uses SHA-256 hash function:
     * ----------------------------------------------------------------------------------------------------------------------------
     * 1: Private Key, Private Key Base58
     * 2: Public key
     * 3: Perform SHA-256 hashing on the public key
     * 4: Perform RIPEMD-160 hashing on the result of SHA-256 of public key
     * 5: Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)
     * 6: Perform double SHA-256 hash on the extended RIPEMD-160 result
     * 7: Take the first 4 bytes of the second SHA-256 hash. This is the address checksum
     * 8: Add the 4 checksum bytes to generate 25-byte binary Bitcoin Address
     * 9: Convert the result from a byte string into a base58 string using Base58Check encoding
     * ----------------------------------------------------------------------------------------------------------------------------
     */
    public static void generateAddress() throws NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());

        ECKey key = new ECKey(SecureRandom.getInstanceStrong());

        // 1: Private Key, Private Key Base58
        System.out.printf("Private key: [%s]%n", key.getPrivateKeyAsHex());
        System.out.printf("Private key Base58: [%s]%n", Base58.encode(key.getPrivKeyBytes()));

        // 2: Public key
        System.out.printf("Public key: [%s]%n", key.getPublicKeyAsHex());

        // 3: Perform SHA-256 hashing on the public key
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] sha256PublicKey = sha256.digest(key.getPubKey());

        // 4: Perform RIPEMD-160 hashing on the result of SHA-256 of public key
        MessageDigest ripemd160 = MessageDigest.getInstance("RipeMD160", "BC");
        byte[] ripemd160PublicKey = ripemd160.digest(sha256PublicKey);

        // 5: Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)
        byte[] versionByte = {0};
        byte[] versionedPublicKey = Bytes.concat(versionByte, ripemd160PublicKey);

        // 6: Perform SHA-256 hash twice on the extended RIPEMD-160 result
        byte[] sha256Ripemd160PublicKey = sha256.digest(sha256.digest(versionedPublicKey));

        // 7: Take the first 4 bytes of the second SHA-256 hash. This is the address checksum
        byte[] checkSum = Arrays.copyOfRange(sha256Ripemd160PublicKey, 0, 4);

        // 8: Add the 4 checksum bytes to generate 25-byte binary Bitcoin Address
        byte[] bitcoinAddressByte = Bytes.concat(versionedPublicKey, checkSum);

        // 9: Convert the result from a byte string into a base58 string using Base58Check encoding
        String bitcoinAddress = Base58.encode(bitcoinAddressByte);
        System.out.printf("Bitcoin Address: [%s]%n", bitcoinAddress);
        System.out.printf("See the address on the Bitcoin blockchain: [https://blockchain.com/btc/address/%s]%n", bitcoinAddress);

    }

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException {
        generateAddress();
    }
}
