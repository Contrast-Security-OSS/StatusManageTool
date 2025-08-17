/*
 * MIT License
 * Copyright (c) 2025 Contrast Security Japan G.K.
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 */

package com.contrastsecurity.statusmanagetool;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public enum StatusEnum {
    REPORTED("報告済", "Reported", true, false),
    SUSPICIOUS("疑わしい", "Suspicious", true, false),
    CONFIRMED("確認済", "Confirmed", true, false),
    NOTAPROBLEM("問題無し", "NotAProblem", true, true),
    REMEDIATED("修復済", "Remediated", true, false),
    REMEDIATED_AUTO_VERIFIED("修復済 - 自動検証", null, false, false),
    FIXED("修正完了", "Fixed", true, false);

    private String label;
    private String value;
    private boolean operable;
    private boolean requiredSubStatus;

    private StatusEnum(String label, String value, boolean operable, boolean requiredSubStatus) {
        this.label = label;
        this.value = value;
        this.operable = operable;
        this.requiredSubStatus = requiredSubStatus;
    }

    public String getLabel() {
        return label;
    }

    public String getValue() {
        return value;
    }

    public boolean isRequiredSubStatus() {
        return requiredSubStatus;
    }

    public static Optional<StatusEnum> fromValue(String value) {
        return Arrays.stream(StatusEnum.values()).filter(e -> value != null && value.equals(e.value)).findFirst();
    }

    public static StatusEnum[] comboValues() {
        List<StatusEnum> list = new ArrayList<StatusEnum>();
        for (StatusEnum e : StatusEnum.values()) {
            if (e.operable) {
                list.add(e);
            }
        }
        return list.toArray(new StatusEnum[0]);
    }
}
