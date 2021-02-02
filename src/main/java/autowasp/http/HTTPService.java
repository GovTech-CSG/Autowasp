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

import burp.IHttpService;

import java.io.Serializable;

public class HTTPService implements IHttpService, Serializable {

    private final String host;
    private final int port;
    private final String protocol;

    public HTTPService(IHttpService copy) {
        this.host = copy.getHost();
        this.port = copy.getPort();
        this.protocol = copy.getProtocol();
    }

    @Override
    public String getHost() {
        if(host == null){
            return "";
        }
        return host;
    }

    @Override
    public int getPort() {
        return port;
    }

    @Override
    public String getProtocol() {
        if(protocol == null){
            return "";
        }
        return protocol;
    }
}
