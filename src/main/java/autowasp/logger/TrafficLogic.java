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
package autowasp.logger;

import autowasp.Autowasp;
import autowasp.http.HTTPRequestResponse;
import autowasp.http.InterceptProxyMessage;
import autowasp.logger.entryTable.LoggerEntry;
import autowasp.logger.instancesTable.InstanceEntry;
import burp.IRequestInfo;
import burp.IResponseInfo;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

//  The TrafficLogic implements the logic for processing traffic related functions.
public class TrafficLogic {
	private final Autowasp extender;
    boolean secHeaderFlag = false;
    boolean cookieOverallFlag = false;
    boolean httpRequestFlag = false;
    boolean basicAuthenticationFlag = false;
    boolean serverDetailFlag = false;
    boolean serverErrorLeakedInfoFlag = false;
    boolean corHeadersFlag = false;
    boolean unauthorisedDisclosureHostnameFlag = false;
    boolean urlManipulationFlag = false;
    boolean xssFlag = false;
    boolean cgiFlag = false;
    boolean cgiUrls = false;
    boolean httpVerbFlag = false;
    private String evidence;
    private String trafficMsg;
    private String flag;
    private InterceptProxyMessage message;
    private HTTPRequestResponse messageInfo;
    private IRequestInfo requestInfo;
    private IResponseInfo responseInfo ;
    private TrafficInstance affectedInstancesList;
    private List<String> requestHeaderList = new ArrayList<>();
    private List<String> responseHeaderList = new ArrayList<>();
	public final ArrayList<String> cgiUrlList;
	public final String burpCollaboratorHost;


    final ArrayList<String> httpVerbList = new ArrayList<>();
	
	public TrafficLogic(Autowasp extender) {
		this.extender = extender;
		this.buildHttpVerbList();
		this.cgiUrlList = new ArrayList<>();
		this.burpCollaboratorHost = this.extender.iBurpCollaboratorClientContext.generatePayload(true);
	}

	// Method to automate and flag network traffic findings
	public void classifyTraffic(InterceptProxyMessage message) {
		this.resetLogMsg();
		this.message = message;
		messageInfo = this.message.getMessageInfo();
		requestInfo = extender.helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest());
		responseInfo = extender.helpers.analyzeResponse(messageInfo.getResponse());
		requestHeaderList = requestInfo.getHeaders();
		responseHeaderList = responseInfo.getHeaders();

		if(!httpRequestFlag && messageInfo.getHttpService().getProtocol().equals("http")) {
			verifyHTTPRequest();
		}
		if (!serverDetailFlag) {
			verifyServerInfoLeakage();
		}
		if (!serverErrorLeakedInfoFlag) {
			verifyServerErrorLeakage();
		}
		if (!basicAuthenticationFlag) {
			verifyBasicAuthentication();
		}
		if (!urlManipulationFlag) {
			try {
				if (responseInfo.getStatusCode() == 302 && messageInfo.getHttpService().getProtocol().equals("http")) {
					verifyUrlManipulation();
				}
			} catch (Exception e) {
				extender.stdout.println("Exception occurred at classifyTraffic()");
			}
		}
		if (!corHeadersFlag) {
			verifyCorHeaders();
		}
		if (!httpVerbFlag) {
			verifyHttpVerbRequest();
		}
		if (!secHeaderFlag) {
			verifyXContentHeaders();
		}
		
		// TODO: Always Monitoring CGI modules
		//verifyCGIModules();
	}

	// Method to inspect response content headers
	private void verifyXContentHeaders() {
		boolean xcontentFlag = false;
		this.trafficMsg = "";
		this.evidence = "";
		for (String header : responseHeaderList) {
			String[] tokens = header.split(":");
			if(tokens[0].toLowerCase().contains("x-content-type-options")) {
				this.trafficMsg = "[+] X-Content-Type-Options header implemented\n";
				this.evidence += header + "\n";
				xcontentFlag = true;
			}
			if(tokens[0].toLowerCase().contains("x-frame-options")) {
				this.trafficMsg = "[+] X-Frame-Options implemented\n";
				this.evidence += header + "\n";
				xcontentFlag = true;
			}
			if(tokens[0].toLowerCase().contains("x-xss-protection")) {
				this.trafficMsg = "[+] X-XSS-Protection implemented\n";
				this.evidence += header + "\n";
				xcontentFlag = true;
			}
			if(tokens[0].toLowerCase().contains("content-type")) {
				this.trafficMsg = "[+] Content-Type implemented\n";
				this.evidence += header + "\n";
				xcontentFlag = true;
			}
		}
		
		if (xcontentFlag) {
			this.secHeaderFlag = true;
			affectedInstancesList.setXContentHeaders();
			this.flag = "Content frame(s) implementation";
			storeTrafficFinding();
		}
		
	}

	// Method to verify HTTP verb request submission
	private void verifyHttpVerbRequest() {
		try {
			byte[] request = messageInfo.getRequest();
			if (request != null) {
				String request_string = extender.helpers.bytesToString(request); 			
				String[] lines = request_string.split("\n");

				if (lines[0].contains("POST")) {
					this.evidence = "";
				
					String host = messageInfo.getHttpService().getHost();
					int port = messageInfo.getHttpService().getPort();
				
					for (String method: httpVerbList) {
						String newRequest_string = request_string.replace("POST", method);
						byte[] newRequest = extender.helpers.stringToBytes(newRequest_string);
						byte[] newResponse = extender.callbacks.makeHttpRequest(host, port, true, newRequest);
						IResponseInfo newResponseInfo = extender.helpers.analyzeResponse(newResponse);
						int newStatusCode = newResponseInfo.getStatusCode();
						
						if (newStatusCode < 400) {
							this.evidence +=  "Ran method: " + method + "  and response status code returns " + newStatusCode + "\n";
						}
					}
					
					if (!this.evidence.equals("")) {
						this.trafficMsg = "[+] Possible dangerous HTTP method could be used on this site";
					}
					else {
						this.trafficMsg = "[+] No dangerous HTTP method could be used on this site";
					}
					this.flag = "HTTP verb testing";
					affectedInstancesList.setHttpVerb();
					this.httpVerbFlag = true;
					storeTrafficFinding();
				}
			}
		}
		catch(Exception e) {
			extender.stdout.println("Exception occurred at verifyHttpVerbRequest()");
		}
	}

	// Method to inspect for CORS headers
	private void verifyCorHeaders() {
		for (String header : responseHeaderList) {
			if (header.toLowerCase().contains("access-control-allow-origin: *")) {
				this.corHeadersFlag = true;
				this.trafficMsg = "[+] Insecure implementation of CORS Header\n";
				this.evidence = header + "\n";
				this.flag = "CORS headers implementation";
				affectedInstancesList.setCorHeaders();
				storeTrafficFinding();
			}
		}
	}

	// Method to inspect for URL manipulation
	private void verifyUrlManipulation() {
		if (requestHeaderList.size() != 0) {
			try {
				String directory = requestHeaderList.get(0).split(" ")[1];
				
				// ensure there is no slash behind the URL and a .ext file
				if (!directory.endsWith("/") && !directory.contains(".")) {
					
					this.urlManipulationFlag = true;
					int port = 80;
					String urlString = "https://" + burpCollaboratorHost + directory;
					URL url;
					
					url = new URL(urlString);

					
					byte[] maliciousRequest = extender.helpers.buildHttpRequest(url);
					IRequestInfo newRequestInfo = extender.helpers.analyzeRequest(maliciousRequest);
					List<String> newRequestHeaderList = newRequestInfo.getHeaders();
					byte[] newResponse = extender.callbacks.makeHttpRequest(burpCollaboratorHost, port, false, maliciousRequest);
					IResponseInfo newResponseInfo = extender.helpers.analyzeResponse(newResponse);
					List<String> newResponseHeaderList = newResponseInfo.getHeaders();
					
					if (newResponseInfo.getStatusCode() == 302) {
						for (String header: newResponseHeaderList) {
							String location = "location: " + urlString;
							if (header.toLowerCase().contains(location)) {
								this.trafficMsg = "[+] Manipulation of URL to redirect victim IS possible on this site";
								this.evidence = "MANIPULATED REQUEST\n"; 
								for (String newHeader: newRequestHeaderList) {
									this.evidence += newHeader + "\n";
								}
								this.evidence += "\n\nRESPONSE\n";
								for (String newHeader: newResponseHeaderList) {
									this.evidence += newHeader + "\n";
								}							}
							else {
								this.trafficMsg = "[+] Manipulation of URL to redirect victim IS NOT possible on this site";
								this.evidence = "MANIPULATED REQUEST\n"; 
								for (String newHeader: newRequestHeaderList) {
									this.evidence += newHeader + "\n";
								}
								this.evidence += "\n\nRESPONSE\n";
								for (String newHeader: newResponseHeaderList) {
									this.evidence += newHeader + "\n";
								}		
							}
						}
					}
					else {
						this.trafficMsg = "[+] Manipulation of URL to redirect victim IS NOT possible on this site";
						this.evidence = "MANIPULATED REQUEST\n"; 
						for (String newHeader: newRequestHeaderList) {
							this.evidence += newHeader + "\n";
						}
						this.evidence += "\n\nRESPONSE\n";
						for (String newHeader: newResponseHeaderList) {
							this.evidence += newHeader + "\n";
						}		
					}
					
					this.urlManipulationFlag = true;
					this.flag = "URL Manipulation";
					storeTrafficFinding();
				}
				
			} catch (MalformedURLException e) {
				extender.stdout.println("MalformedURLException at verifyUrlManipulation()" );
			}
		}
	}

	// Method to identify the use of basic authentication headers
	private void verifyBasicAuthentication() {
		for (String header : requestHeaderList) {
			if (header.toLowerCase().contains("authorization: basic")) {
				String[] tokens = header.split(" ");
				String encode = tokens[2];
				byte[] decodeBytes = extender.helpers.base64Decode(encode);
				String decode;
				decode = new String(decodeBytes , StandardCharsets.UTF_8);

				this.basicAuthenticationFlag = true;
				this.flag = "Base64 weak authentication request";
				this.trafficMsg = "[+] Basic Authentication request is being used\n";
				this.trafficMsg += "Encoded found: " + encode + "\n";
				this.trafficMsg += "Decoded found: " + decode + "\n";
				this.evidence = header + "\n";
				this.affectedInstancesList.setBase64();
				storeTrafficFinding();
			}
		}
	}

	/*
	// Method to identify for CGI modules. Still in development.
	private void verifyCGIModules() {
		String directory = responseHeaderList.get(0).split(" ")[1];
		
		if (cgiFlag && directory.contains("cgi") && responseInfo.getStatusCode() == 200) {
			String url = requestInfo.getUrl().toString();
			if (cgiUrlList.contains(url)) {
				for (TrafficEntry temp : extender.trafficLog) {
					if (temp.affectedInstancesList.isCGI) {
						temp.evidence += "URL :" + url + " returns : " + responseInfo.getStatusCode() + "\n";
						this.cgiUrlList.add(url);
					}
				}
			}
		}
		else if (directory.contains("cgi") && responseInfo.getStatusCode() == 200) {
			String url = requestInfo.getUrl().toString();
			this.cgiUrlList.add(url);
			this.trafficMsg = "[+] CGI modules are enabled on this web server";
			this.evidence = "URL :" + url + " returns : " + responseInfo.getStatusCode() + "\n";
			this.cgiFlag = true;
			this.flag = "CGI Modules enabled";
			affectedInstancesList.setCGI();
			storeTrafficFinding();
		}
	}*/

	// Method to inspect for server error leakage
	private void verifyServerErrorLeakage() {
		try {
			String header = responseHeaderList.get(2);
			String[] tokens = header.split(":");
			
			if (header.toLowerCase().contains("server") && tokens[1].length() != 1 && responseInfo.getStatusCode() >= 500) {
				trafficMsg = "[+] Potential Server Details : " + tokens[1] + "from server error page\n";
				
				this.serverErrorLeakedInfoFlag = true;
				this.flag = "Server response header revealed from error response";
				affectedInstancesList.setServerErrorInfoLeaked();
				this.evidence = header + "\n";
				storeTrafficFinding();
			}
		}
		catch (Exception e) {
			extender.stdout.println("Exception occurred at verifyServerErrorLeakage");
		}

	}

	// Method to inspect for server info
	private void verifyServerInfoLeakage() {
		boolean toLog = false;
		try {
			String header = responseHeaderList.get(2);
			String[] tokens = header.split(":");

			if(header.toLowerCase().contains("server") && tokens[1].length() != 1) {
				trafficMsg = "[+] Potential Server Details : " + tokens[1] + "\n";
				toLog = true;
			}
			
			if (header.toLowerCase().contains("x-powered-by") && tokens[1].length() != 1) {
				trafficMsg = "[+] Web Server powered by : " + tokens[1] + "\n";
				toLog = true;
			}
			if (toLog) {
				this.serverDetailFlag = true;
				this.flag = "Server Information Leakage";
				affectedInstancesList.setServerInfoLeaked();
				this.evidence = header + "\n";
				storeTrafficFinding();
			}
		}
		catch(Exception e) {
			extender.stdout.println("Exception occurred at verifyServerInfoLeakage");
		}
	}

	// Method to inspect for non-secure network traffic
	private void verifyHTTPRequest() {
		this.httpRequestFlag = true;
		trafficMsg = "[+] A proxy intercepted a request on : " + messageInfo.getHttpService().getHost();
		flag = "Communication over unencrypted channel";
		affectedInstancesList.setUnencrypted();
		
		if (responseInfo.getStatusCode() == 200) {
			trafficMsg += "\n[+] Server response with " + responseInfo.getStatusCode();
			trafficMsg += "\n[+] Potential sensitive information being transmitted over non-SSL connections";	
		}
		else if(responseInfo.getStatusCode() == 302 || responseInfo.getStatusCode() == 301 || responseInfo.getStatusCode() == 304) {
			trafficMsg += "\n[+] Server response return "+ responseInfo.getStatusCode();
			trafficMsg +="\nRedirection Message from a HTTP Request detected";
		}
		evidence = responseHeaderList.get(0) + "\n";
		evidence += responseHeaderList.get(1) + "\n";
		evidence += responseHeaderList.get(2) + "\n";
		evidence += responseHeaderList.get(3) + "\n";
		evidence += responseHeaderList.get(4) + "\n";
		storeTrafficFinding();
	}

	// Method to build HTTP Verb list
	private void buildHttpVerbList() {
		this.httpVerbList.add("POST");
		this.httpVerbList.add("PUT");
		this.httpVerbList.add("DELETE");
		this.httpVerbList.add("TRACE");
		this.httpVerbList.add("TRACK");
		this.httpVerbList.add("CONNECT");
		this.httpVerbList.add("PROPFIND");
		this.httpVerbList.add("PROPPATCH");
		this.httpVerbList.add("MKCOL");
		this.httpVerbList.add("MOVE");
		this.httpVerbList.add("LOCK");
		this.httpVerbList.add("UNLOCK");
		this.httpVerbList.add("VERSION-CONTROL");
		this.httpVerbList.add("REPORT");
		this.httpVerbList.add("CHECKOUT");
		this.httpVerbList.add("CHECKIN");
		this.httpVerbList.add("UNCHECKOUT");
		this.httpVerbList.add("MKWORKSPACE");
		this.httpVerbList.add("UPDATE");
		this.httpVerbList.add("LABEL");
		this.httpVerbList.add("MERGE");
		this.httpVerbList.add("BASELINE-CONTROL");
		this.httpVerbList.add("MKACTIVITY");
		this.httpVerbList.add("ORDERPATCH");
		this.httpVerbList.add("ACL");
		this.httpVerbList.add("PATCH");
		this.httpVerbList.add("SEARCH");
		this.httpVerbList.add("ARBITARY");
	}

	// Method to clear log message
	private void resetLogMsg() {
	    evidence = null;
	    trafficMsg = null;
	    affectedInstancesList = new TrafficInstance();
	    message = null;
	    messageInfo = null;
	    requestInfo = null;
	    responseInfo = null;
	    requestHeaderList.clear();
	    responseHeaderList.clear();
	    
	}

	// Method to store traffic findings to Autowasp
	private void storeTrafficFinding() {
		String host = messageInfo.getHttpService().getHost();
		String action = "Automated Traffic";
		String vulnType = flag;
		String issue = "";
		String comments = "Automated Traffic logging detected the following issue: " + flag;
		LoggerEntry findingEntry = new LoggerEntry(host, action, vulnType, issue);
		findingEntry.setEvidence(evidence);

		URL url = extender.helpers.analyzeRequest(message.getMessageInfo()).getUrl();
		String confidence = "Certain";
		String severity = "~";
		HTTPRequestResponse requestResponse = new HTTPRequestResponse(message.getMessageInfo());
		InstanceEntry instanceEntry = new InstanceEntry(url, confidence, severity, requestResponse);
		findingEntry.addInstance(instanceEntry);
		findingEntry.setPenTesterComments(comments + "\n" + trafficMsg);

		extender.loggerTableModel.addAllLoggerEntry(findingEntry);

		this.resetLogMsg();
	}
}
