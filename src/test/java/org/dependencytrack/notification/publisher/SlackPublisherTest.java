/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.notification.publisher;

import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;

public class SlackPublisherTest extends AbstractWebhookPublisherTest<SlackPublisher> {

    public SlackPublisherTest() {
        super(DefaultNotificationPublishers.SLACK, new SlackPublisher());
    }

    @Override
    public void testInformWithDataSourceMirroringNotification() {
        super.testInformWithDataSourceMirroringNotification();

        // TODO
    }

    @Override
    public void testInformWithNewVulnerabilityNotification() {
        super.testInformWithNewVulnerabilityNotification();

        // TODO
    }

    @Override
    public void testInformWithProjectAuditChangeNotification() {
        super.testInformWithProjectAuditChangeNotification();

        verify(postRequestedFor(anyUrl())
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson("""
                        {
                          "blocks": [
                            {
                        	  "type": "header",
                        	  "text": {
                        	    "type": "plain_text",
                        		"text": "Project Audit Change"
                        	  }
                        	},
                        	{
                        	  "type": "context",
                        	  "elements": [
                        	    {
                        		  "text": "*INFORMATIONAL*  |  *PORTFOLIO*",
                        		  "type": "mrkdwn"
                        		}
                        	  ]
                        	},
                        	{
                        	  "type": "divider"
                        	},
                        	{
                        	  "type": "section",
                        	  "text": {
                        	    "text": "Analysis Decision: Finding Suppressed",
                        		"type": "plain_text"
                        	  },
                        	  "fields": [
                        	    {
                        		  "type": "mrkdwn",
                        		  "text": "*Analysis State*"
                        		},
                        		{
                        		  "type": "plain_text",
                        		  "emoji": true,
                        		  "text": "FALSE_POSITIVE"
                        		},
                        		{
                        		  "type": "mrkdwn",
                        		  "text": "*Suppressed*"
                        		},
                        		{
                        		  "type": "plain_text",
                        		  "text": "true"
                        		},
                        		{
                        		  "type": "mrkdwn",
                        		  "text": "*VulnID*"
                        		},
                        		{
                        		  "type": "plain_text",
                        		  "text": "INT-001"
                        		},
                        		{
                        		  "type": "mrkdwn",
                        		  "text": "*Severity*"
                        		},
                        		{
                        		  "type": "plain_text",
                        		  "text": "MEDIUM"
                        		},
                        		{
                        		  "type": "mrkdwn",
                        		  "text": "*Source*"
                        		},
                        		{
                        		  "type": "plain_text",
                        		  "text": "INTERNAL"
                        		}
                        	  ]
                        	},
                            {
                        	  "type": "section",
                        	  "fields": [
                        		{
                        		  "type": "mrkdwn",
                        		  "text": "*Component*"
                        		},
                        		{
                        		  "type": "plain_text",
                        		  "text": "componentName : componentVersion"
                        		},
                        		{
                        		  "type": "mrkdwn",
                        		  "text": "*Project*"
                        		},
                        		{
                        		  "type": "plain_text",
                        		  "text": "pkg:maven/org.acme/projectName@projectVersion"
                        		}
                        	  ]
                        	},
                        	{
                        	  "type": "actions",
                        	  "elements": [
                        	    {
                        		  "type": "button",
                        		  "text": {
                        		    "type": "plain_text",
                        			"text": "View Project"
                        		  },
                        		  "action_id": "actionId-1",
                        		  "url": "https://example.com/projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95"
                        		},
                        		{
                        		  "type": "button",
                        		  "text": {
                        		    "type": "plain_text",
                        			"text": "View Component"
                        		  },
                        		  "action_id": "actionId-2",
                        		  "url": "https://example.com/components/94f87321-a5d1-4c2f-b2fe-95165debebc6"
                        		},
                        	    {
                        		  "type": "button",
                        		  "text": {
                        		    "type": "plain_text",
                        			"text": "View Vulnerability"
                        		  },
                        		  "action_id": "actionId-3",
                        		  "url": "https://example.com/vulnerabilities/INTERNAL/INT-001"
                        		}
                        	  ]
                        	}
                          ]
                        }
                        """)));
    }

}
