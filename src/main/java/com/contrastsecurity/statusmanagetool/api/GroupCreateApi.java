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
import java.util.StringJoiner;

import org.eclipse.jface.preference.IPreferenceStore;
import org.eclipse.swt.widgets.Shell;

import com.contrastsecurity.statusmanagetool.json.ContrastJson;
import com.contrastsecurity.statusmanagetool.model.Organization;
import com.contrastsecurity.statusmanagetool.preference.PreferenceConstants;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import okhttp3.MediaType;
import okhttp3.RequestBody;

public class GroupCreateApi extends Api {

    private List<Organization> orgs;

    public GroupCreateApi(Shell shell, IPreferenceStore ps, Organization org, List<Organization> orgs) {
        super(shell, ps, org);
        this.orgs = orgs;
    }

    @Override
    protected String getUrl() {
        return String.format("%s/api/ng/superadmin/ac/groups/organizational?expand=skip_links", this.contrastUrl); //$NON-NLS-1$
    }

    @Override
    protected RequestBody getBody() throws Exception {
        String groupName = this.ps.getString(PreferenceConstants.GROUP_NAME);
        MediaType mediaTypeJson = MediaType.parse("application/json; charset=UTF-8"); //$NON-NLS-1$
        StringJoiner scopes = new StringJoiner(","); //$NON-NLS-1$
        for (Organization org : this.orgs) {
            if (!org.isLocked()) {
                scopes.add(String.format("{\"org\":{\"id\":\"%s\",\"role\":\"admin\"},\"app\":{\"exceptions\":[],\"role\":\"admin\"}}", org.getOrganization_uuid())); //$NON-NLS-1$
            }
        }
        String json = String.format("{\"name\":\"%s\",\"users\":[\"%s\"],\"scopes\":[%s]}", groupName, this.userName, scopes); //$NON-NLS-1$
        return RequestBody.create(json, mediaTypeJson);
    }

    @Override
    protected Object convert(String response) {
        Gson gson = new Gson();
        Type contType = new TypeToken<ContrastJson>() {
        }.getType();
        ContrastJson contrastJson = gson.fromJson(response, contType);
        return contrastJson.getSuccess();
    }

}
