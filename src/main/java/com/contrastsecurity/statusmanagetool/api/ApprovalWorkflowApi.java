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

import com.contrastsecurity.statusmanagetool.json.PendingStatusApprovalJson;
import com.contrastsecurity.statusmanagetool.model.ItemForVulnerability;
import com.contrastsecurity.statusmanagetool.model.Organization;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import okhttp3.MediaType;
import okhttp3.RequestBody;

public class ApprovalWorkflowApi extends Api {

    private List<ItemForVulnerability> vulns;
    private boolean approved;
    private String note;

    public ApprovalWorkflowApi(Shell shell, IPreferenceStore ps, Organization org, List<ItemForVulnerability> vulns, boolean approved, String note) {
        super(shell, ps, org);
        this.vulns = vulns;
        this.approved = approved;
        this.note = note;
    }

    @Override
    protected String getUrl() {
        String orgId = this.org.getOrganization_uuid();
        return String.format("%s/api/ng/%s/approval-workflow/traces/pending-status", this.contrastUrl, orgId); //$NON-NLS-1$
    }

    @Override
    protected RequestBody getBody() throws Exception {
        MediaType mediaTypeJson = MediaType.parse("application/json; charset=UTF-8"); //$NON-NLS-1$
        String traceArrayStr = "";
        if (!this.vulns.isEmpty()) {
            traceArrayStr = this.vulns.stream().map(vul -> vul.getVulnerability().getUuid()).collect(Collectors.joining("\",\"", "\"", "\""));
        }
        String json = String.format("{\"traces\":[%s],\"approved\":%s}", traceArrayStr, this.approved); //$NON-NLS-1$
        if (!this.approved) {
            json = String.format("{\"traces\":[%s],\"approved\":%s,\"comment\":\"%s\"}", traceArrayStr, this.approved, this.note.replace("\r\n", "\n").replace("\n", "\\n")); //$NON-NLS-1$
        }
        return RequestBody.create(json, mediaTypeJson);
    }

    @Override
    protected Object convert(String response) {
        Gson gson = new Gson();
        Type contType = new TypeToken<PendingStatusApprovalJson>() {
        }.getType();
        PendingStatusApprovalJson json = gson.fromJson(response, contType);
        return json;
    }

}
