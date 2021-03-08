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

import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;

import java.awt.event.InputEvent;

public class ContextMenuInvocation implements IContextMenuInvocation {

    private final InputEvent inputEvent;
    private final int toolFlag;
    private final byte invocationContext;
    private final int[] selectionBounds;
    private final HTTPRequestResponse[] selectedMessages;
    private final ScanIssue[] scanIssues;

    public ContextMenuInvocation(IContextMenuInvocation copy) {
        this.inputEvent = copy.getInputEvent();
        this.toolFlag = copy.getToolFlag();
        this.invocationContext = copy.getInvocationContext();
        this.selectionBounds = copy.getSelectionBounds();

        IHttpRequestResponse[] httpRequestResponses = copy.getSelectedMessages();
        HTTPRequestResponse[] httpRequestResponses1 = new HTTPRequestResponse[httpRequestResponses.length];
        for (int i = 0; i < httpRequestResponses.length; i++)
        {
            httpRequestResponses1[i] = new HTTPRequestResponse(httpRequestResponses[i]);
        }
        this.selectedMessages = httpRequestResponses1;
        this.scanIssues = (ScanIssue[]) copy.getSelectedIssues();
    }

    /**
     * Used to indicate that the context menu is being invoked in a request
     * editor.
     */
    public static final byte CONTEXT_MESSAGE_EDITOR_REQUEST = 0;
    /**
     * Used to indicate that the context menu is being invoked in a response
     * editor.
     */
    public static final byte CONTEXT_MESSAGE_EDITOR_RESPONSE = 1;
    /**
     * Used to indicate that the context menu is being invoked in a non-editable
     * request viewer.
     */
    public static final byte CONTEXT_MESSAGE_VIEWER_REQUEST = 2;
    /**
     * Used to indicate that the context menu is being invoked in a non-editable
     * response viewer.
     */
    public static final byte CONTEXT_MESSAGE_VIEWER_RESPONSE = 3;
    /**
     * Used to indicate that the context menu is being invoked in the Target
     * site map tree.
     */
    public static final byte CONTEXT_TARGET_SITE_MAP_TREE = 4;
    /**
     * Used to indicate that the context menu is being invoked in the Target
     * site map table.
     */
    public static final  byte CONTEXT_TARGET_SITE_MAP_TABLE = 5;
    /**
     * Used to indicate that the context menu is being invoked in the Proxy
     * history.
     */
    public static final byte CONTEXT_PROXY_HISTORY = 6;
    /**
     * Used to indicate that the context menu is being invoked in the Scanner
     * results.
     */
    public static final byte CONTEXT_SCANNER_RESULTS = 7;
    /**
     * Used to indicate that the context menu is being invoked in the Intruder
     * payload positions editor.
     */
    public static final byte CONTEXT_INTRUDER_PAYLOAD_POSITIONS = 8;
    /**
     * Used to indicate that the context menu is being invoked in an Intruder
     * attack results.
     */
    public static final byte CONTEXT_INTRUDER_ATTACK_RESULTS = 9;
    /**
     * Used to indicate that the context menu is being invoked in a search
     * results window.
     */
    public static final byte CONTEXT_SEARCH_RESULTS = 10;

    /**
     * This method can be used to retrieve the native Java input event that was
     * the trigger for the context menu invocation.
     *
     * @return The <code>InputEvent</code> that was the trigger for the context
     * menu invocation.
     */
    public InputEvent getInputEvent() {
        return inputEvent;
    }

    /**
     * This method can be used to retrieve the Burp tool within which the
     * context menu was invoked.
     *
     * @return A flag indicating the Burp tool within which the context menu was
     * invoked. Burp tool flags are defined in the
     * <code>IBurpExtenderCallbacks</code> interface.
     */
    public int getToolFlag() {
        return toolFlag;
    }

    /**
     * This method can be used to retrieve the context within which the menu was
     * invoked.
     *
     * @return An index indicating the context within which the menu was
     * invoked. The indices used are defined within this interface.
     */
    public byte getInvocationContext() {
        return invocationContext;
    }

    /**
     * This method can be used to retrieve the bounds of the user's selection
     * into the current message, if applicable.
     *
     * @return An int[2] array containing the start and end offsets of the
     * user's selection in the current message. If the user has not made any
     * selection in the current message, both offsets indicate the position of
     * the caret within the editor. If the menu is not being invoked from a
     * message editor, the method returns <code>null</code>.
     */
    public int[] getSelectionBounds() {
        if(selectionBounds == null){
            return new int[]{};
        }
        return selectionBounds;
    }

    /**
     * This method can be used to retrieve details of the HTTP requests /
     * responses that were shown or selected by the user when the context menu
     * was invoked.
     *
     * <b>Note:</b> For performance reasons, the objects returned from this
     * method are tied to the originating context of the messages within the
     * Burp UI. For example, if a context menu is invoked on the Proxy intercept
     * panel, then the
     * <code>IHttpRequestResponse</code> returned by this method will reflect
     * the current contents of the interception panel, and this will change when
     * the current message has been forwarded or dropped. If your extension
     * needs to store details of the message for which the context menu has been
     * invoked, then you should query those details from the
     * <code>IHttpRequestResponse</code> at the time of invocation, or you
     * should use
     * <code>IBurpExtenderCallbacks.saveBuffersToTempFiles()</code> to create a
     * persistent read-only copy of the
     * <code>IHttpRequestResponse</code>.
     *
     * @return An array of <code>IHttpRequestResponse</code> objects
     * representing the items that were shown or selected by the user when the
     * context menu was invoked. This method returns <code>null</code> if no
     * messages are applicable to the invocation.
     */
    public HTTPRequestResponse[] getSelectedMessages() {
        if(selectedMessages == null){
            return new HTTPRequestResponse[]{};
        }
        return selectedMessages;
    }

    /**
     * This method can be used to retrieve details of the Scanner issues that
     * were selected by the user when the context menu was invoked.
     *
     * @return An array of <code>IScanIssue</code> objects representing the
     * issues that were selected by the user when the context menu was invoked.
     * This method returns <code>null</code> if no Scanner issues are applicable
     * to the invocation.
     */
    public ScanIssue[] getSelectedIssues() {
        if(scanIssues == null){
            return new ScanIssue[]{};
        }
        return scanIssues;
    }
}
