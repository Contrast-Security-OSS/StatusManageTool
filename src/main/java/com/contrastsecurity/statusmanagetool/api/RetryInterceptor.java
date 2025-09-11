package com.contrastsecurity.statusmanagetool.api;

import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.Response;

public class RetryInterceptor implements Interceptor {

    Logger logger = LogManager.getLogger("statusmanagetool");

    private final int maxRetries;
    private final long retryDelayMillis;

    public RetryInterceptor(int maxRetries, long retryDelayMillis) {
        this.maxRetries = maxRetries;
        this.retryDelayMillis = retryDelayMillis;
    }

    @Override
    public Response intercept(Chain chain) throws IOException {
        Request request = chain.request();
        Response response = null;
        IOException lastException = null;

        for (int retryCount = 0; retryCount < maxRetries; retryCount++) {
            try {
                response = chain.proceed(request);
                if (response.isSuccessful()) {
                    return response;
                }
                if (shouldRetry(response.code()) && retryCount < maxRetries) {
                    logger.warn("Request failed with status code {}, retrying... ({}/{})", response.code(), (retryCount + 1), maxRetries);
                    response.close();
                    retryCount++;
                    Thread.sleep(retryDelayMillis);
                    continue;
                }
                return response;
            } catch (IOException e) {
                lastException = e;
                logger.warn(request.url());
                logger.warn("Request failed, retrying by interceptor... (" + (retryCount + 1) + "/" + maxRetries + ")");
                // System.err.println("Request failed, retrying... (" + (i + 1) + "/" + maxRetries + ")");
                // try {
                // Thread.sleep(retryDelayMillis);
                // } catch (InterruptedException ie) {
                // Thread.currentThread().interrupt();
                // throw new IOException("Retry interrupted", ie);
                // }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Retry interrupted", e);
            }
        }

        if (response != null) {
            return response;
        } else if (lastException != null) {
            throw lastException;
        } else {
            throw new IOException("Failed to execute request after " + maxRetries + " retries without a clear exception.");
        }
    }

    private boolean shouldRetry(int code) {
        return code == 408 || code == 429 || (code >= 500 && code <= 599);
    }
}
