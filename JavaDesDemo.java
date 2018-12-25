/*
 *  * Copyright (c) MASSCLOUDS 2013 All Rights Reserved
 *   */
package com.massclouds.cmobile.center.common.util;

import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 *  * <p>DES加解密算法实现。<p>
 *   * 
 *    * 创建日期 2014年2月18日<br>
 *     * @author li_ming<br>
 *      */
public class EncryptUtil {
    public static String KEY = "massclou";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
 *   * des加密算法
 *       * @param encryptString 需要加密字符
 *           * @param encryptKey 加密key
 *               * @return
 *                   * @throws Exception
 *                       */
    public static String getDesString(String encryptString, String encryptKey) throws Exception {
        SecretKeySpec key = new SecretKeySpec(encryptKey.getBytes(), "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
        if (encryptString.length() % 8 != 0) {
            cipher = Cipher.getInstance("DES/ECB/ZeroBytePadding");
        }
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedData = cipher.doFinal(encryptString.getBytes());
        BASE64Encoder base64en = new BASE64Encoder();
        return base64en.encode(encryptedData);
    }

    /**
 *   * des 解密算法
 *       * @param decryptString 需要解密字符
 *           * @param decryptKey
 *               * @return
 *                   * @throws Exception
 *                       */
    public static String getEncString(String decryptString, String decryptKey) throws Exception {
        BASE64Decoder base64De = new BASE64Decoder();
        byte[] byteMi = base64De.decodeBuffer(decryptString);
        SecretKeySpec key = new SecretKeySpec(decryptKey.getBytes(), "DES");

        Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
        if (byteMi.length % 8 != 0) {
            cipher = Cipher.getInstance("DES/ECB/ZeroBytePadding");
        }

        cipher.init(Cipher.DECRYPT_MODE, key);
        byte decryptedData[] = cipher.doFinal(byteMi);

        return new String(decryptedData).replaceAll("\0", "");
    }

    public static void main(String[] args) {
        String pass;
        try {
            pass = EncryptUtil.getDesString("12345678", EncryptUtil.KEY);
            System.out.println(pass);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

