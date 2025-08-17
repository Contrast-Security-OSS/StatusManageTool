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
import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.jface.preference.IPreferenceStore;
import org.eclipse.swt.widgets.Shell;

import com.contrastsecurity.statusmanagetool.StatusEnum;
import com.contrastsecurity.statusmanagetool.SubStatusEnum;
import com.contrastsecurity.statusmanagetool.json.ContrastJson;
import com.contrastsecurity.statusmanagetool.model.ItemForVulnerability;
import com.contrastsecurity.statusmanagetool.model.Organization;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import okhttp3.MediaType;
import okhttp3.RequestBody;

public class StatusMarkApi extends Api {

    private List<ItemForVulnerability> vulns;
    private StatusEnum status;
    private SubStatusEnum subStatus;
    private String note;

    public StatusMarkApi(Shell shell, IPreferenceStore ps, Organization org, List<ItemForVulnerability> vulns, StatusEnum status, SubStatusEnum subStatus, String note) {
        super(shell, ps, org);
        this.vulns = vulns;
        this.status = status;
        this.subStatus = subStatus;
        this.note = note;
    }

    @Override
    protected String getUrl() {
        String orgId = this.org.getOrganization_uuid();
        return String.format("%s/api/ng/%s/orgtraces/mark", this.contrastUrl, orgId);
    }

    @Override
    protected RequestBody getBody() throws Exception {
        MediaType mediaTypeJson = MediaType.parse("application/json; charset=UTF-8");
        String traceArrayStr = "";
        if (!this.vulns.isEmpty()) {
            traceArrayStr = this.vulns.stream().map(vul -> vul.getVulnerability().getUuid()).collect(Collectors.joining("\",\"", "\"", "\""));
        }
        String json = String.format("{\"traces\":[%s],\"status\":\"%s\",\"note\":\"%s\"}", traceArrayStr, this.status.getValue(),
                this.note.replace("\r\n", "\n").replace("\n", "\\n"));
        if (status == StatusEnum.NOTAPROBLEM) {
            json = String.format("{\"traces\":[%s],\"status\":\"%s\",\"substatus\":\"%s\",\"note\":\"%s\"}", traceArrayStr, this.status.getValue(), this.subStatus.getValue(),
                    this.note.replace("\r\n", "\n").replace("\n", "\\n"));
        }
        return RequestBody.create(json, mediaTypeJson);
    }

    @Override
    protected Object convert(String response) {
        Gson gson = new Gson();
        Type contType = new TypeToken<ContrastJson>() {
        }.getType();
        ContrastJson json = gson.fromJson(response, contType);
        return json;
    }

}
