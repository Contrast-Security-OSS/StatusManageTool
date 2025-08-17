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

package com.contrastsecurity.statusmanagetool.api;

import java.lang.reflect.Type;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.List;

import org.eclipse.jface.preference.IPreferenceStore;
import org.eclipse.swt.widgets.Shell;

import com.contrastsecurity.statusmanagetool.DetectTypeEnum;
import com.contrastsecurity.statusmanagetool.VulnTypeEnum;
import com.contrastsecurity.statusmanagetool.json.TraceFilterBySecurityStandardJson;
import com.contrastsecurity.statusmanagetool.model.ItemForVulnerability;
import com.contrastsecurity.statusmanagetool.model.Organization;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import okhttp3.MediaType;
import okhttp3.RequestBody;

public class TracesApi extends Api {

    private final static int LIMIT = 25;
    private VulnTypeEnum vulnType;
    private DetectTypeEnum detectType;
    private Date startDate;
    private Date endDate;
    private int offset;
    private final DateTimeFormatter datetimeformatter = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss"); //$NON-NLS-1$

    public TracesApi(Shell shell, IPreferenceStore ps, Organization org, VulnTypeEnum vulnType, DetectTypeEnum detectType, Date startDate, Date endDate, int offset) {
        super(shell, ps, org);
        this.vulnType = vulnType;
        this.detectType = detectType;
        this.startDate = startDate;
        this.endDate = endDate;
        this.offset = offset;
    }

    @Override
    protected String getUrl() {
        String orgId = this.org.getOrganization_uuid();
        return String.format("%s/api/ng/organizations/%s/orgtraces/ui?expand=application&offset=%d&limit=%d&sort=-severity", this.contrastUrl, orgId, this.offset, LIMIT); //$NON-NLS-1$
    }

    @Override
    protected RequestBody getBody() throws Exception {
        MediaType mediaTypeJson = MediaType.parse("application/json; charset=UTF-8"); //$NON-NLS-1$
        String json = String.format("{\"quickFilter\":\"%s\",\"timestampFilter\":\"%s\",\"startDate\":\"%s\",\"endDate\":\"%s\"}", this.vulnType.name(), this.detectType.name(), //$NON-NLS-1$
                this.startDate.getTime(), this.endDate.getTime());
        return RequestBody.create(json, mediaTypeJson);
    }

    @Override
    protected Object convert(String response) {
        Gson gson = new Gson();
        Type contType = new TypeToken<TraceFilterBySecurityStandardJson>() {
        }.getType();
        TraceFilterBySecurityStandardJson json = gson.fromJson(response, contType);
        this.totalCount = json.getCount();
        List<ItemForVulnerability> items = json.getItems();
        for (ItemForVulnerability vul : items) {
            LocalDateTime lastLdt = LocalDateTime.ofInstant(Instant.ofEpochMilli(Long.parseLong(vul.getVulnerability().getLastDetected())), ZoneId.systemDefault());
            vul.getVulnerability().setLastDetectedStr(datetimeformatter.format(lastLdt));
            LocalDateTime firstLdt = LocalDateTime.ofInstant(Instant.ofEpochMilli(Long.parseLong(vul.getVulnerability().getFirstDetected())), ZoneId.systemDefault());
            vul.getVulnerability().setFirstDetectedStr(datetimeformatter.format(firstLdt));
        }
        return items;
    }

}
