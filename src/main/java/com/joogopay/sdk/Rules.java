package com.joogopay.sdk;

import java.util.List;
import java.util.Map;

/**
 * Code generated from the JSON rule data under protocol/data. DO NOT EDIT.
 *
 * <p>An empty codes list means the gateway has no allowlist for that currency; the SDK does not reject on the method code there.
 */
final class Rules {
    private Rules() {}

    /** Top-level create-order field rules, from protocol/data/request-rules.json. */
    static final List<String> CREATE_REQUIRED_TEXT_FIELDS = List.of("merchantOrderNo", "currency");
    static final String AMOUNT_PATTERN = "^(0|[1-9][0-9]{0,15})(\\.[0-9]{1,2})?$";
    static final String WEBHOOK_URL_PREFIX = "https://";

    static final Map<String, String> METHOD_EXTRA_FIELDS = Map.ofEntries(
            Map.entry("APPLE_PAY", "applePay"),
            Map.entry("BANK_CARD", "bankCard"),
            Map.entry("BANK_TRANSFER", "bankTransfer"),
            Map.entry("BD_BKASH", "bdBkash"),
            Map.entry("BD_NAGAD", "bdNagad"),
            Map.entry("BREB", "breb"),
            Map.entry("CASH", "cash"),
            Map.entry("CASH_APP", "cashApp"),
            Map.entry("CHIME", "chime"),
            Map.entry("CREDIT_CARD", "creditCard"),
            Map.entry("CVU", "cvu"),
            Map.entry("E_WALLET", "eWallet"),
            Map.entry("GOOGLE_PAY", "googlePay"),
            Map.entry("ID_BANK_TRANSFER", "idBankTransfer"),
            Map.entry("ID_DANA", "idDana"),
            Map.entry("ID_GOPAY", "idGopay"),
            Map.entry("ID_LINKAJA", "idLinkaja"),
            Map.entry("ID_OVO", "idOvo"),
            Map.entry("ID_QRIS", "idQris"),
            Map.entry("ID_SHOPEEPAY", "idShopeepay"),
            Map.entry("ID_VA", "idVa"),
            Map.entry("IN_IFSC", "inIfsc"),
            Map.entry("IN_UPI", "inUpi"),
            Map.entry("KHIPU", "khipu"),
            Map.entry("MACH", "mach"),
            Map.entry("NEQUI", "nequi"),
            Map.entry("NETELLER", "neteller"),
            Map.entry("P2P", "p2p"),
            Map.entry("PAGO46", "pago46"),
            Map.entry("PAGO_FACIL", "pagoFacil"),
            Map.entry("PAPARA", "papara"),
            Map.entry("PAYPAL", "paypal"),
            Map.entry("PH_DF_BANK", "phDfBank"),
            Map.entry("PH_DF_WALLET", "phDfWallet"),
            Map.entry("PH_GCASH", "phGcash"),
            Map.entry("PH_GCASH_QR", "phGcashQr"),
            Map.entry("PH_GRAB", "phGrab"),
            Map.entry("PH_MAYA", "phMaya"),
            Map.entry("PH_MAYA_QR", "phMayaQr"),
            Map.entry("PH_NATIVE_GCASH", "phNativeGcash"),
            Map.entry("PH_QRIS", "phQris"),
            Map.entry("PIX", "pix"),
            Map.entry("PK_BANK", "pkBank"),
            Map.entry("PK_EASYPAISA", "pkEasypaisa"),
            Map.entry("PK_EASYPAISA_QRPH", "pkEasypaisaQrph"),
            Map.entry("PK_JAZZCASH", "pkJazzcash"),
            Map.entry("PK_JAZZCASH_QRPH", "pkJazzcashQrph"),
            Map.entry("PSE", "pse"),
            Map.entry("QRIS", "qris"),
            Map.entry("RAPIPAGO", "rapipago"),
            Map.entry("SBP", "sbp"),
            Map.entry("SERVIFACIL", "serviFacil"),
            Map.entry("SKRILL", "skrill"),
            Map.entry("SPEI", "spei"),
            Map.entry("TH_BANK_CARD", "thBankCard"),
            Map.entry("TH_BANK_TRANSFER", "thBankTransfer"),
            Map.entry("TH_PROMPTPAY", "thPromptpay"),
            Map.entry("TH_TRUEMONEY", "thTruemoney"),
            Map.entry("TRANSFIYA", "transfiya"),
            Map.entry("USDT-BEP20", "usdtBep20"),
            Map.entry("USDT-ERC20", "usdtErc20"),
            Map.entry("USDT-TRC20", "usdtTrc20"),
            Map.entry("WEBPAY", "webpay")
    );

    record Rule(List<String> codes, List<String> required, Map<String, List<String>> byMethod, List<String> allowEmpty, Map<String, List<String>> optionalNullableStringsByMethod) {
        Rule(List<String> codes, List<String> required, Map<String, List<String>> byMethod) {
            this(codes, required, byMethod, List.of(), Map.of());
        }
    }

    static final Map<String, Rule> PAYMENT_METHOD_RULES = Map.ofEntries(
            Map.entry("ARS", new Rule(List.of("BANK_TRANSFER", "CVU", "QRIS"), List.of("documentNumber", "documentType", "email", "firstName", "lastName"), Map.ofEntries(Map.entry("CVU", List.of("phone")), Map.entry("QRIS", List.of("phone"))))),
            Map.entry("BDT", new Rule(List.of("BD_BKASH", "BD_NAGAD"), List.of("accountName", "email", "mobile"), Map.of())),
            Map.entry("BRL", new Rule(List.of("PIX"), List.of(), Map.of())),
            Map.entry("CLP", new Rule(List.of("KHIPU", "MACH", "PAGO46", "WEBPAY"), List.of("customerEmail", "customerName", "documentNumber", "documentType"), Map.of())),
            Map.entry("COP", new Rule(List.of("BREB", "NEQUI", "PSE"), List.of(), Map.ofEntries(Map.entry("BREB", List.of("customerEmail", "customerName", "customerPhone", "documentNumber", "documentType"))))),
            Map.entry("IDR", new Rule(List.of("ID_DANA", "ID_GOPAY", "ID_LINKAJA", "ID_OVO", "ID_QRIS", "ID_SHOPEEPAY", "ID_VA"), List.of("accountName", "bankCode", "email", "mobile"), Map.of())),
            Map.entry("INR", new Rule(List.of("IN_UPI"), List.of("accountName", "email", "mobile"), Map.of())),
            Map.entry("MXN", new Rule(List.of("CASH", "OXXO", "SPEI"), List.of(), Map.of())),
            Map.entry("PEN", new Rule(List.of("BANK_TRANSFER", "CASH", "E_WALLET"), List.of("customerEmail", "customerName", "customerPhone", "documentNumber", "documentType"), Map.of())),
            Map.entry("PHP", new Rule(List.of("PH_GCASH", "PH_GCASH_QR", "PH_GRAB", "PH_MAYA", "PH_MAYA_QR", "PH_NATIVE_GCASH", "PH_QRIS"), List.of(), Map.of())),
            Map.entry("PKR", new Rule(List.of("PK_EASYPAISA", "PK_EASYPAISA_QRPH", "PK_JAZZCASH", "PK_JAZZCASH_QRPH"), List.of(), Map.of())),
            Map.entry("TRY", new Rule(List.of("BANK_TRANSFER"), List.of("customerName"), Map.of())),
            Map.entry("USD", new Rule(List.of("CASH_APP"), List.of("name", "phone", "email", "ipAddress"), Map.of()))
    );

    static final Map<String, Rule> PAYOUT_METHOD_RULES = Map.ofEntries(
            Map.entry("ARS", new Rule(List.of("BANK_TRANSFER"), List.of("accountNo", "accountType", "documentNumber", "documentType", "email", "firstName", "lastName", "phone"), Map.of(), List.of(), Map.ofEntries(Map.entry("BANK_TRANSFER", List.of("address"))))),
            Map.entry("BDT", new Rule(List.of("BD_BKASH", "BD_NAGAD"), List.of("accountName", "accountNo", "email", "mobile"), Map.of())),
            Map.entry("BRL", new Rule(List.of("PIX"), List.of("key", "keyType"), Map.of())),
            Map.entry("CLP", new Rule(List.of("BANK_TRANSFER"), List.of("accountName", "accountNo", "accountType", "bankCode", "customerEmail", "customerPhone", "documentNumber", "documentType"), Map.of())),
            Map.entry("COP", new Rule(List.of("BANK_CARD", "BANK_TRANSFER", "BREB", "TRANSFIYA"), List.of("customerEmail", "customerName", "customerPhone", "documentNumber", "documentType"), Map.ofEntries(Map.entry("BANK_CARD", List.of("accountNo", "bankName")), Map.entry("BANK_TRANSFER", List.of("accountNo", "bankName")), Map.entry("BREB", List.of("accountNo"))))),
            Map.entry("IDR", new Rule(List.of("ID_BANK_TRANSFER", "ID_DANA", "ID_GOPAY", "ID_LINKAJA", "ID_OVO", "ID_SHOPEEPAY"), List.of("accountName", "accountNo", "bankCode", "email", "mobile"), Map.of())),
            Map.entry("INR", new Rule(List.of("IN_IFSC", "IN_UPI"), List.of("email", "mobile", "name"), Map.ofEntries(Map.entry("IN_IFSC", List.of("account", "ifsc"))))),
            Map.entry("MXN", new Rule(List.of("BANK_TRANSFER"), List.of("accountName", "accountNo", "accountType", "bankCode", "bankName"), Map.of())),
            Map.entry("PEN", new Rule(List.of("BANK_TRANSFER", "E_WALLET"), List.of("accountName", "accountNo", "bankCode", "customerEmail", "customerPhone", "documentNumber", "documentType"), Map.ofEntries(Map.entry("BANK_TRANSFER", List.of("accountType", "cciNo"))))),
            Map.entry("PHP", new Rule(List.of("PH_DF_BANK", "PH_DF_WALLET", "PH_GCASH", "PH_MAYA"), List.of("accountName", "accountNo", "email", "mobile"), Map.ofEntries(Map.entry("PH_DF_BANK", List.of("bankCode")), Map.entry("PH_DF_WALLET", List.of("bankCode"))))),
            Map.entry("PKR", new Rule(List.of("PK_BANK", "PK_EASYPAISA", "PK_JAZZCASH"), List.of("accountNo", "cnic", "mobile"), Map.ofEntries(Map.entry("PK_BANK", List.of("bankCode"))))),
            Map.entry("TRY", new Rule(List.of("BANK_TRANSFER", "PAPARA"), List.of("accountName", "accountNo"), Map.ofEntries(Map.entry("BANK_TRANSFER", List.of("bankCode", "bankName"))))),
            Map.entry("USD", new Rule(List.of("CASH_APP", "PAYPAL", "CHIME"), List.of("name", "phone", "email", "accountNo", "firstName", "lastName", "dateOfBirth", "countryOfResidence", "stateOfResidence", "cardCity", "cardStreet", "cardPostCode"), Map.of()))
    );

}
