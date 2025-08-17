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

import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public enum FilterEnum {
    RULE_NAME("ルール名", 1),
    SEVERITY("重大度", 2),
    APP_NAME("アプリケーション", 3),
    ORG_NAME("組織", 6),
    STATUS("ステータス", 4),
    PENDING_STATUS("保留中ステータス", 5);

    private FilterEnum(String label, int dialogOrder) {
        this.label = label;
        this.dialogOrder = dialogOrder;
    }

    private String label;
    private int dialogOrder;

    public String getLabel() {
        return label;
    }

    public static List<FilterEnum> sortedValues() {
        List<FilterEnum> list = Arrays.asList(FilterEnum.values());
        Collections.sort(list, new Comparator<FilterEnum>() {
            @Override
            public int compare(FilterEnum e1, FilterEnum e2) {
                return Integer.valueOf(e1.dialogOrder).compareTo(Integer.valueOf(e2.dialogOrder));
            }
        });
        return list;
    }
}
