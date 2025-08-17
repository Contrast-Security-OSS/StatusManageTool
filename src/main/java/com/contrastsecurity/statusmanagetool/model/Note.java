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

package com.contrastsecurity.statusmanagetool.model;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;

import org.apache.commons.text.StringEscapeUtils;

public class Note {
    private String note;
    private String creation;
    private String creator;
    private String last_modification;
    private String last_updater;
    private List<Property> properties;
    private final DateTimeFormatter datetimeformatter = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss"); //$NON-NLS-1$

    public String getNote() {
        // 文字実体参照を変換
        return StringEscapeUtils.unescapeHtml4(note);
    }

    public void setNote(String note) {
        this.note = note;
    }

    public String getCreation() {
        return creation;
    }

    public String getCreationStr() {
        LocalDateTime creationLdt = LocalDateTime.ofInstant(Instant.ofEpochMilli(Long.parseLong(creation)), ZoneId.systemDefault());
        return datetimeformatter.format(creationLdt);
    }

    public void setCreation(String creation) {
        this.creation = creation;
    }

    public String getCreator() {
        if (this.creator != null) {
            return creator;
        }
        return "";
    }

    public void setCreator(String creator) {
        this.creator = creator;
    }

    public String getLast_modification() {
        return last_modification;
    }

    public void setLast_modification(String last_modification) {
        this.last_modification = last_modification;
    }

    public String getLast_updater() {
        return last_updater;
    }

    public void setLast_updater(String last_updater) {
        this.last_updater = last_updater;
    }

    public List<Property> getProperties() {
        return properties;
    }

    public void setProperties(List<Property> properties) {
        this.properties = properties;
    }

    public String getProperty(String key) {
        for (Property prop : this.properties) {
            if (prop.getName().equals(key)) {
                if (prop.getValue().length() > 0) {
                    return prop.getValue();
                }
            }
        }
        return "";
    }

    @Override
    public String toString() {
        return this.getNote();
    }

}
