/*
 * Copyright (c) 2020 Government Technology Agency
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
import burp.IHttpRequestResponsePersisted;
import burp.IHttpService;

import java.io.Serializable;

public class HTTPRequestResponse implements IHttpRequestResponse, IHttpRequestResponsePersisted, Serializable {

    private byte[] request;
    private byte[] response;
    private String comment;
    private String highlight;
    private HTTPService httpService;

    public HTTPRequestResponse(IHttpRequestResponse copy) {
        this.request = copy.getRequest();
        this.response = copy.getResponse();
        this.comment = copy.getComment();
        this.highlight = copy.getHighlight();
        this.httpService = new HTTPService(copy.getHttpService());
    }

    @Override
    public byte[] getRequest() {
        if(request == null) {
            return new byte[]{};
        }
        return request;
    }

    @Override
    public void setRequest(byte[] message) {
        request = message;
    }

    @Override
    public byte[] getResponse() {
        if(response == null) {
            return new byte[]{};
        }
        return response;
    }

    @Override
    public void setResponse(byte[] message) {
        response = message;
    }

    @Override
    public String getComment() {
        return comment;
    }

    @Override
    public void setComment(String comment) {
        this.comment = comment;
    }

    @Override
    public String getHighlight() {
        return highlight;
    }

    @Override
    public void setHighlight(String color) {
        this.highlight = color;
    }

    @Override
    public HTTPService getHttpService() {
        return httpService;
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        this.httpService = new HTTPService(httpService);
    }

    @Override
    public void deleteTempFiles() {

    }
}
