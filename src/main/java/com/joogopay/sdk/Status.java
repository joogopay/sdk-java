package com.joogopay.sdk;

import java.util.List;
import java.util.Set;

/**
 * Public status vocabulary and constants.
 *
 * <p>Amounts, fees and rates are always decimal strings, never double or float.
 */
public final class Status {

    public static final String PENDING = "PENDING";
    public static final String PROCESSING = "PROCESSING";
    public static final String SUCCEEDED = "SUCCEEDED";
    public static final String FAILED = "FAILED";
    public static final String EXPIRED = "EXPIRED";
    public static final String CANCELED = "CANCELED";

    /**
     * The six external statuses shared by the API, webhooks and the hosted checkout; the former
     * PAID, CREATED and EXCEPTION are retired.
     */
    public static final Set<String> ALL =
            Set.of(PENDING, PROCESSING, SUCCEEDED, FAILED, EXPIRED, CANCELED);

    public static final String WEBHOOK_ORDER_TYPE_PAYMENT = "PAYMENT";
    public static final String WEBHOOK_ORDER_TYPE_PAYOUT = "PAYOUT";

    /** Public money fields; the guard test asserts each one is a decimal string. */
    public static final List<String> MONEY_FIELDS = List.of(
            "amount", "paidAmount", "minAmount", "maxAmount", "usdRate",
            "balance", "lockBalance", "paymentBalance", "paymentLockBalance",
            "payoutBalance", "payoutLockBalance");

    private Status() {
    }
}
