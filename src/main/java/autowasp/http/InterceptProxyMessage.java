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

import burp.IInterceptedProxyMessage;

import java.net.InetAddress;

public class InterceptProxyMessage implements IInterceptedProxyMessage {

    private int interceptAction;
    private final HTTPRequestResponse httpRequestResponse;
    private final String listenerInterface;
    private final InetAddress clientIPAddr;
    private final int msgRef;

    public InterceptProxyMessage(IInterceptedProxyMessage copy){
        this.msgRef = copy.getMessageReference();
        this.interceptAction = copy.getInterceptAction();
        this.httpRequestResponse = new HTTPRequestResponse(copy.getMessageInfo());
        this.listenerInterface = copy.getListenerInterface();
        this.clientIPAddr = copy.getClientIpAddress();
    }

    @Override
    public int getMessageReference() {
        return msgRef;
    }

    @Override
    public HTTPRequestResponse getMessageInfo() {
        return httpRequestResponse;
    }

    @Override
    public int getInterceptAction() {
        return interceptAction;
    }

    @Override
    public void setInterceptAction(int interceptAction) {
        this.interceptAction = interceptAction;
    }

    @Override
    public String getListenerInterface() {
        return listenerInterface;
    }

    @Override
    public InetAddress getClientIpAddress() {
        return clientIPAddr;
    }
}
