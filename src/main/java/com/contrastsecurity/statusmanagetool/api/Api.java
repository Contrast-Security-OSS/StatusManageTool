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

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.Header;
import org.apache.http.HttpHeaders;
import org.apache.http.message.BasicHeader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.jface.preference.IPreferenceStore;
import org.eclipse.swt.widgets.Shell;
import org.jasypt.util.text.BasicTextEncryptor;

import com.contrastsecurity.statusmanagetool.Main;
import com.contrastsecurity.statusmanagetool.Messages;
import com.contrastsecurity.statusmanagetool.exception.ApiException;
import com.contrastsecurity.statusmanagetool.exception.NonApiException;
import com.contrastsecurity.statusmanagetool.model.Organization;
import com.contrastsecurity.statusmanagetool.preference.PreferenceConstants;

import okhttp3.Authenticator;
import okhttp3.Credentials;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.Route;

public abstract class Api {

    public enum HttpMethod {
        GET,
        POST,
        PUT,
        DELETE
    }

    Logger logger = LogManager.getLogger("vulnstatusmanagetool"); //$NON-NLS-1$

    protected Shell shell;
    protected IPreferenceStore ps;
    protected Organization org;
    protected String contrastUrl;
    protected String userName;
    protected String serviceKey;
    protected boolean success;
    protected int totalCount;
    private List<Integer> ignoreStatusCodes;

    public Api(Shell shell, IPreferenceStore ps, Organization org) {
        this.shell = shell;
        this.ps = ps;
        this.org = org;
        this.contrastUrl = this.ps.getString(PreferenceConstants.CONTRAST_URL);
        this.serviceKey = this.ps.getString(PreferenceConstants.SERVICE_KEY);
        this.userName = this.ps.getString(PreferenceConstants.USERNAME);
        this.ignoreStatusCodes = new ArrayList<Integer>();
    }

    public void setIgnoreStatusCodes(List<Integer> ignoreStatusCodes) {
        this.ignoreStatusCodes = ignoreStatusCodes;
    }

    public Object get() throws Exception {
        String response = this.getResponse(HttpMethod.GET);
        return this.convert(response);
    }

    public Object post() throws Exception {
        String response = this.getResponse(HttpMethod.POST);
        return this.convert(response);
    }

    public Object put() throws Exception {
        String response = this.getResponse(HttpMethod.PUT);
        return this.convert(response);
    }

    public Object delete() throws Exception {
        String response = this.getResponse(HttpMethod.DELETE);
        return this.convert(response);
    }

    public boolean isSuccess() {
        return success;
    }

    public int getTotalCount() {
        return totalCount;
    }

    protected abstract String getUrl();

    protected abstract Object convert(String response);

    protected List<Header> getHeaders() {
        List<Header> headers = new ArrayList<Header>();
        String apiKey = this.org.getApikey();
        String auth = String.format("%s:%s", this.userName, this.serviceKey); //$NON-NLS-1$
        byte[] encodedAuth = Base64.encodeBase64(auth.getBytes(StandardCharsets.ISO_8859_1));
        String authHeader = new String(encodedAuth);
        headers.add(new BasicHeader(HttpHeaders.ACCEPT, "application/json")); //$NON-NLS-1$
        headers.add(new BasicHeader("API-Key", apiKey)); //$NON-NLS-1$
        headers.add(new BasicHeader(HttpHeaders.AUTHORIZATION, authHeader));
        return headers;
    }

    protected RequestBody getBody() throws Exception {
        return null;
    }

    protected String getResponse(HttpMethod httpMethod) throws Exception {
        String url = this.getUrl();
        logger.trace(url);
        OkHttpClient.Builder clientBuilder = new OkHttpClient.Builder();
        Request.Builder requestBuilder = null;
        switch (httpMethod) {
            case POST:
                requestBuilder = new Request.Builder().url(url).post(getBody());
                break;
            case PUT:
                requestBuilder = new Request.Builder().url(url).put(getBody());
                break;
            case DELETE:
                requestBuilder = new Request.Builder().url(url).delete(getBody());
                break;
            default:
                requestBuilder = new Request.Builder().url(url).get();
        }
        List<Header> headers = this.getHeaders();
        for (Header header : headers) {
            requestBuilder.addHeader(header.getName(), header.getValue());
        }
        OkHttpClient httpClient = null;
        Request request = requestBuilder.build();
        Response response = null;
        try {
            int connectTimeout = Integer.parseInt(this.ps.getString(PreferenceConstants.CONNECTION_TIMEOUT));
            int sockettTimeout = Integer.parseInt(this.ps.getString(PreferenceConstants.SOCKET_TIMEOUT));
            clientBuilder.readTimeout(sockettTimeout, TimeUnit.MILLISECONDS).connectTimeout(connectTimeout, TimeUnit.MILLISECONDS);

            if (this.ps.getBoolean(PreferenceConstants.IGNORE_SSLCERT_CHECK)) {
                SSLContext sslContext = SSLContext.getInstance("SSL"); //$NON-NLS-1$
                TrustManager[] trustAllCerts = getTrustManager();
                sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
                SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
                clientBuilder.sslSocketFactory(sslSocketFactory, (X509TrustManager) trustAllCerts[0]);
                clientBuilder.hostnameVerifier(new HostnameVerifier() {
                    @Override
                    public boolean verify(String hostname, SSLSession session) {
                        return true;
                    }
                });
            }

            if (this.ps.getBoolean(PreferenceConstants.PROXY_YUKO)) {
                clientBuilder.proxy(new Proxy(Proxy.Type.HTTP,
                        new InetSocketAddress(this.ps.getString(PreferenceConstants.PROXY_HOST), Integer.parseInt(this.ps.getString(PreferenceConstants.PROXY_PORT)))));
                if (!this.ps.getString(PreferenceConstants.PROXY_AUTH).equals("none")) { //$NON-NLS-1$
                    Authenticator proxyAuthenticator = null;
                    // プロキシ認証あり
                    if (this.ps.getString(PreferenceConstants.PROXY_AUTH).equals("input")) { //$NON-NLS-1$
                        proxyAuthenticator = new Authenticator() {

                            @Override
                            public Request authenticate(Route route, Response response) throws IOException {
                                String credential = Credentials.basic(ps.getString(PreferenceConstants.PROXY_TMP_USER), ps.getString(PreferenceConstants.PROXY_TMP_PASS));
                                return response.request().newBuilder().header("Proxy-Authorization", credential).build(); //$NON-NLS-1$
                            }
                        };
                    } else {

                        BasicTextEncryptor encryptor = new BasicTextEncryptor();
                        encryptor.setPassword(Main.MASTER_PASSWORD);
                        try {
                            String proxy_pass = encryptor.decrypt(this.ps.getString(PreferenceConstants.PROXY_PASS));
                            proxyAuthenticator = new Authenticator() {
                                @Override
                                public Request authenticate(Route route, Response response) throws IOException {
                                    String credential = Credentials.basic(ps.getString(PreferenceConstants.PROXY_USER), proxy_pass);
                                    return response.request().newBuilder().header("Proxy-Authorization", credential).build(); //$NON-NLS-1$
                                }
                            };
                        } catch (Exception e) {
                            throw new ApiException("プロキシパスワードの復号化に失敗しました。\\r\\nパスワードの設定をやり直してください。");
                        }
                    }
                    clientBuilder.proxyAuthenticator(proxyAuthenticator);
                }
            }
            httpClient = clientBuilder.build();
            try {
                response = httpClient.newCall(request).execute();
                if (response.code() == 200 || this.ignoreStatusCodes.contains(response.code())) {
                    return response.body().string();
                } else if (response.code() == 400) {
                    throw new ApiException(response.body().string());
                } else if (response.code() == 401 || response.code() == 403) {
                    throw new ApiException(response.body().string());
                } else {
                    logger.warn(response.code());
                    logger.warn(response.body().string());
                    throw new NonApiException(String.valueOf(response.code()));
                }
            } catch (IOException ioe) {
                throw ioe;
            }
        } catch (Exception e) {
            StringWriter stringWriter = new StringWriter();
            PrintWriter printWriter = new PrintWriter(stringWriter);
            e.printStackTrace(printWriter);
            String trace = stringWriter.toString();
            logger.error(url);
            logger.error(trace);
            throw e;
        } finally {
            try {
                if (response != null) {
                    response.body().close();
                }
            } catch (Exception e) {
                StringWriter stringWriter = new StringWriter();
                PrintWriter printWriter = new PrintWriter(stringWriter);
                e.printStackTrace(printWriter);
                String trace = stringWriter.toString();
                logger.error(trace);
                throw e;
            }
        }
    }

    private static TrustManager[] getTrustManager() {
        TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[] {};
            }
        } };
        return trustAllCerts;
    }

}
