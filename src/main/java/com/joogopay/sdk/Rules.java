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
    static final List<String> CREATE_REQUIRED_TEXT_FIELDS = Collections8.list("merchantOrderNo", "currency");
    static final String AMOUNT_PATTERN = "^(0|[1-9][0-9]{0,15})(\\.[0-9]{1,2})?$";
    static final String WEBHOOK_URL_PREFIX = "https://";

    static final Map<String, String> METHOD_EXTRA_FIELDS = Collections8.mapEntries(
            Collections8.entry("APPLE_PAY", "applePay"),
            Collections8.entry("BANK_CARD", "bankCard"),
            Collections8.entry("BANK_TRANSFER", "bankTransfer"),
            Collections8.entry("BD_BKASH", "bdBkash"),
            Collections8.entry("BD_NAGAD", "bdNagad"),
            Collections8.entry("BREB", "breb"),
            Collections8.entry("CASH", "cash"),
            Collections8.entry("CASH_APP", "cashApp"),
            Collections8.entry("CHIME", "chime"),
            Collections8.entry("CREDIT_CARD", "creditCard"),
            Collections8.entry("CVU", "cvu"),
            Collections8.entry("E_WALLET", "eWallet"),
            Collections8.entry("GOOGLE_PAY", "googlePay"),
            Collections8.entry("ID_BANK_TRANSFER", "idBankTransfer"),
            Collections8.entry("ID_DANA", "idDana"),
            Collections8.entry("ID_GOPAY", "idGopay"),
            Collections8.entry("ID_LINKAJA", "idLinkaja"),
            Collections8.entry("ID_OVO", "idOvo"),
            Collections8.entry("ID_QRIS", "idQris"),
            Collections8.entry("ID_SHOPEEPAY", "idShopeepay"),
            Collections8.entry("ID_VA", "idVa"),
            Collections8.entry("IN_IFSC", "inIfsc"),
            Collections8.entry("IN_UPI", "inUpi"),
            Collections8.entry("KHIPU", "khipu"),
            Collections8.entry("MACH", "mach"),
            Collections8.entry("NEQUI", "nequi"),
            Collections8.entry("NETELLER", "neteller"),
            Collections8.entry("P2P", "p2p"),
            Collections8.entry("PAGO46", "pago46"),
            Collections8.entry("PAGO_FACIL", "pagoFacil"),
            Collections8.entry("PAPARA", "papara"),
            Collections8.entry("PAYPAL", "paypal"),
            Collections8.entry("PH_DF_BANK", "phDfBank"),
            Collections8.entry("PH_DF_WALLET", "phDfWallet"),
            Collections8.entry("PH_GCASH", "phGcash"),
            Collections8.entry("PH_GCASH_QR", "phGcashQr"),
            Collections8.entry("PH_GRAB", "phGrab"),
            Collections8.entry("PH_MAYA", "phMaya"),
            Collections8.entry("PH_MAYA_QR", "phMayaQr"),
            Collections8.entry("PH_NATIVE_GCASH", "phNativeGcash"),
            Collections8.entry("PH_QRIS", "phQris"),
            Collections8.entry("PIX", "pix"),
            Collections8.entry("PK_BANK", "pkBank"),
            Collections8.entry("PK_EASYPAISA", "pkEasypaisa"),
            Collections8.entry("PK_EASYPAISA_QRPH", "pkEasypaisaQrph"),
            Collections8.entry("PK_JAZZCASH", "pkJazzcash"),
            Collections8.entry("PK_JAZZCASH_QRPH", "pkJazzcashQrph"),
            Collections8.entry("PSE", "pse"),
            Collections8.entry("QRIS", "qris"),
            Collections8.entry("RAPIPAGO", "rapipago"),
            Collections8.entry("SBP", "sbp"),
            Collections8.entry("SERVIFACIL", "serviFacil"),
            Collections8.entry("SKRILL", "skrill"),
            Collections8.entry("SPEI", "spei"),
            Collections8.entry("TH_BANK_CARD", "thBankCard"),
            Collections8.entry("TH_BANK_TRANSFER", "thBankTransfer"),
            Collections8.entry("TH_PROMPTPAY", "thPromptpay"),
            Collections8.entry("TH_TRUEMONEY", "thTruemoney"),
            Collections8.entry("TRANSFIYA", "transfiya"),
            Collections8.entry("USDT-BEP20", "usdtBep20"),
            Collections8.entry("USDT-ERC20", "usdtErc20"),
            Collections8.entry("USDT-TRC20", "usdtTrc20"),
            Collections8.entry("WEBPAY", "webpay")
    );

    static final class Rule {
        private final List<String> codes, required, allowEmpty;
        private final Map<String, List<String>> byMethod, optionalNullableStringsByMethod;
        Rule(List<String> codes, List<String> required, Map<String, List<String>> byMethod, List<String> allowEmpty, Map<String, List<String>> optionalNullableStringsByMethod) {
            this.codes = codes; this.required = required; this.byMethod = byMethod;
            this.allowEmpty = allowEmpty; this.optionalNullableStringsByMethod = optionalNullableStringsByMethod;
        }
        List<String> codes() { return codes; }
        List<String> required() { return required; }
        List<String> allowEmpty() { return allowEmpty; }
        Map<String, List<String>> byMethod() { return byMethod; }
        Map<String, List<String>> optionalNullableStringsByMethod() { return optionalNullableStringsByMethod; }
        Rule(List<String> codes, List<String> required, Map<String, List<String>> byMethod) {
            this(codes, required, byMethod, Collections8.list(), Collections8.map());
        }
    }

    static final Map<String, Rule> PAYMENT_METHOD_RULES = Collections8.mapEntries(
            Collections8.entry("ARS", new Rule(Collections8.list("BANK_TRANSFER", "CVU", "QRIS"), Collections8.list("documentNumber", "documentType", "email", "firstName", "lastName"), Collections8.mapEntries(Collections8.entry("CVU", Collections8.list("phone")), Collections8.entry("QRIS", Collections8.list("phone"))))),
            Collections8.entry("BDT", new Rule(Collections8.list("BD_BKASH", "BD_NAGAD"), Collections8.list("accountName", "email", "mobile"), Collections8.map())),
            Collections8.entry("BRL", new Rule(Collections8.list("PIX"), Collections8.list(), Collections8.map())),
            Collections8.entry("CLP", new Rule(Collections8.list("KHIPU", "MACH", "PAGO46", "WEBPAY"), Collections8.list("customerEmail", "customerName", "documentNumber", "documentType"), Collections8.map())),
            Collections8.entry("COP", new Rule(Collections8.list("BREB", "NEQUI", "PSE"), Collections8.list(), Collections8.mapEntries(Collections8.entry("BREB", Collections8.list("customerEmail", "customerName", "customerPhone", "documentNumber", "documentType"))))),
            Collections8.entry("IDR", new Rule(Collections8.list("ID_DANA", "ID_GOPAY", "ID_LINKAJA", "ID_OVO", "ID_QRIS", "ID_SHOPEEPAY", "ID_VA"), Collections8.list("accountName", "bankCode", "email", "mobile"), Collections8.map())),
            Collections8.entry("INR", new Rule(Collections8.list("IN_UPI"), Collections8.list("accountName", "email", "mobile"), Collections8.map())),
            Collections8.entry("MXN", new Rule(Collections8.list("CASH", "OXXO", "SPEI"), Collections8.list(), Collections8.map())),
            Collections8.entry("PEN", new Rule(Collections8.list("BANK_TRANSFER", "CASH", "E_WALLET"), Collections8.list("customerEmail", "customerName", "customerPhone", "documentNumber", "documentType"), Collections8.map())),
            Collections8.entry("PHP", new Rule(Collections8.list("PH_GCASH", "PH_GCASH_QR", "PH_GRAB", "PH_MAYA", "PH_MAYA_QR", "PH_NATIVE_GCASH", "PH_QRIS"), Collections8.list(), Collections8.map())),
            Collections8.entry("PKR", new Rule(Collections8.list("PK_EASYPAISA", "PK_EASYPAISA_QRPH", "PK_JAZZCASH", "PK_JAZZCASH_QRPH"), Collections8.list(), Collections8.map())),
            Collections8.entry("TRY", new Rule(Collections8.list("BANK_TRANSFER"), Collections8.list("customerName"), Collections8.map())),
            Collections8.entry("USD", new Rule(Collections8.list("CASH_APP"), Collections8.list("name", "phone", "email", "ipAddress"), Collections8.map()))
    );

    static final Map<String, Rule> PAYOUT_METHOD_RULES = Collections8.mapEntries(
            Collections8.entry("ARS", new Rule(Collections8.list("BANK_TRANSFER"), Collections8.list("accountNo", "accountType", "documentNumber", "documentType", "email", "firstName", "lastName", "phone"), Collections8.map(), Collections8.list(), Collections8.mapEntries(Collections8.entry("BANK_TRANSFER", Collections8.list("address"))))),
            Collections8.entry("BDT", new Rule(Collections8.list("BD_BKASH", "BD_NAGAD"), Collections8.list("accountName", "accountNo", "email", "mobile"), Collections8.map())),
            Collections8.entry("BRL", new Rule(Collections8.list("PIX"), Collections8.list("key", "keyType"), Collections8.map())),
            Collections8.entry("CLP", new Rule(Collections8.list("BANK_TRANSFER"), Collections8.list("accountName", "accountNo", "accountType", "bankCode", "customerEmail", "customerPhone", "documentNumber", "documentType"), Collections8.map())),
            Collections8.entry("COP", new Rule(Collections8.list("BANK_CARD", "BANK_TRANSFER", "BREB", "TRANSFIYA"), Collections8.list("customerEmail", "customerName", "customerPhone", "documentNumber", "documentType"), Collections8.mapEntries(Collections8.entry("BANK_CARD", Collections8.list("accountNo", "bankName")), Collections8.entry("BANK_TRANSFER", Collections8.list("accountNo", "bankName")), Collections8.entry("BREB", Collections8.list("accountNo"))))),
            Collections8.entry("IDR", new Rule(Collections8.list("ID_BANK_TRANSFER", "ID_DANA", "ID_GOPAY", "ID_LINKAJA", "ID_OVO", "ID_SHOPEEPAY"), Collections8.list("accountName", "accountNo", "bankCode", "email", "mobile"), Collections8.map())),
            Collections8.entry("INR", new Rule(Collections8.list("IN_IFSC", "IN_UPI"), Collections8.list("email", "mobile", "name"), Collections8.mapEntries(Collections8.entry("IN_IFSC", Collections8.list("account", "ifsc"))))),
            Collections8.entry("MXN", new Rule(Collections8.list("BANK_TRANSFER"), Collections8.list("accountName", "accountNo", "accountType", "bankCode", "bankName"), Collections8.map())),
            Collections8.entry("PEN", new Rule(Collections8.list("BANK_TRANSFER", "E_WALLET"), Collections8.list("accountName", "accountNo", "bankCode", "customerEmail", "customerPhone", "documentNumber", "documentType"), Collections8.mapEntries(Collections8.entry("BANK_TRANSFER", Collections8.list("accountType", "cciNo"))))),
            Collections8.entry("PHP", new Rule(Collections8.list("PH_DF_BANK", "PH_DF_WALLET", "PH_GCASH", "PH_MAYA"), Collections8.list("accountName", "accountNo", "email", "mobile"), Collections8.mapEntries(Collections8.entry("PH_DF_BANK", Collections8.list("bankCode")), Collections8.entry("PH_DF_WALLET", Collections8.list("bankCode"))))),
            Collections8.entry("PKR", new Rule(Collections8.list("PK_BANK", "PK_EASYPAISA", "PK_JAZZCASH"), Collections8.list("accountNo", "cnic", "mobile"), Collections8.mapEntries(Collections8.entry("PK_BANK", Collections8.list("bankCode"))))),
            Collections8.entry("TRY", new Rule(Collections8.list("BANK_TRANSFER", "PAPARA"), Collections8.list("accountName", "accountNo"), Collections8.mapEntries(Collections8.entry("BANK_TRANSFER", Collections8.list("bankCode", "bankName"))))),
            Collections8.entry("USD", new Rule(Collections8.list("CASH_APP", "PAYPAL", "CHIME"), Collections8.list("name", "phone", "email", "accountNo", "firstName", "lastName", "dateOfBirth", "countryOfResidence", "stateOfResidence", "cardCity", "cardStreet", "cardPostCode"), Collections8.map()))
    );

}
