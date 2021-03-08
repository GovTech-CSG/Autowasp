/*
 * Copyright (c) 2021 Government Technology Agency
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package autowasp.http;

import burp.IHttpRequestResponse;
import burp.IScanIssue;

import java.net.URL;

public class ScanIssue implements IScanIssue {

    private final HTTPService httpService;
    private final URL url;
    private final HTTPRequestResponse[] httpMessages;
    private final String detail;
    private final String severity;
    private final String confidence;
    private final String name;
    private final String remediation;

    public ScanIssue(IScanIssue copy)
    {
        this.name = copy.getIssueName();
        this.detail = copy.getIssueDetail();
        this.severity = copy.getSeverity();
        this.httpService = new HTTPService(copy.getHttpService());
        this.url = copy.getUrl();
        IHttpRequestResponse[] iHttpRequestResponse = copy.getHttpMessages();
        HTTPRequestResponse[] allhttpMessages = new HTTPRequestResponse[iHttpRequestResponse.length];
        for (int i = 0; i < iHttpRequestResponse.length; i++)
        {
            allhttpMessages[i] = new HTTPRequestResponse(iHttpRequestResponse[i]);
        }
        this.httpMessages = allhttpMessages;
        this.confidence = copy.getConfidence();
        this.remediation = copy.getRemediationDetail();
    }

    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return name;
    }

    @Override
    public int getIssueType() {
        return 0;
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    public String getConfidence() {
        return confidence;
    }

    @Override
    public String getIssueBackground() {
        return null;
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        return detail;
    }

    @Override
    public String getRemediationDetail() {
        return remediation;
    }

    @Override
    public HTTPRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    @Override
    public HTTPService getHttpService() {
        return httpService;
    }
}
