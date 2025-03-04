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

import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import org.apache.commons.io.IOUtils;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.vo.AnalysisDecisionChange;
import org.dependencytrack.notification.vo.NewVulnerabilityIdentified;
import org.junit.Test;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.math.BigDecimal;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThatNoException;

public abstract class AbstractPublisherTest<T extends Publisher> extends PersistenceCapableTest {

    final DefaultNotificationPublishers publisher;
    final T publisherInstance;

    AbstractPublisherTest(final DefaultNotificationPublishers publisher, final T publisherInstance) {
        this.publisher = publisher;
        this.publisherInstance = publisherInstance;
    }

    @Test
    public void testInformWithDataSourceMirroringNotification() {
        final var notification = new Notification()
                .scope(NotificationScope.SYSTEM)
                .group(NotificationGroup.DATASOURCE_MIRRORING)
                .title(NotificationConstants.Title.GITHUB_ADVISORY_MIRROR)
                .content("An error occurred mirroring the contents of GitHub Advisories. Check log for details.")
                .level(NotificationLevel.ERROR);

        assertThatNoException()
                .isThrownBy(() -> publisherInstance.inform(notification, createConfig()));
    }

    @Test
    public void testInformWithNewVulnerabilityNotification() {
        final var project = createProject();
        final var component = createComponent(project);
        final var vuln = createVulnerability();

        final var subject = new NewVulnerabilityIdentified(vuln, component, Set.of(project),
                VulnerabilityAnalysisLevel.BOM_UPLOAD_ANALYSIS);

        final var notification = new Notification()
                .scope(NotificationScope.PORTFOLIO)
                .group(NotificationGroup.NEW_VULNERABILITY)
                .level(NotificationLevel.INFORMATIONAL)
                .title(NotificationConstants.Title.NEW_VULNERABILITY)
                .content("")
                .subject(subject);

        assertThatNoException()
                .isThrownBy(() -> publisherInstance.inform(notification, createConfig()));
    }

    @Test
    public void testInformWithProjectAuditChangeNotification() {
        final var project = createProject();
        final var component = createComponent(project);
        final var vuln = createVulnerability();
        final var analysis = createAnalysis(component, vuln);

        final var subject = new AnalysisDecisionChange(vuln, component, project, analysis);

        final var notification = new Notification()
                .scope(NotificationScope.PORTFOLIO)
                .group(NotificationGroup.PROJECT_AUDIT_CHANGE)
                .level(NotificationLevel.INFORMATIONAL)
                .title(NotificationConstants.Title.ANALYSIS_DECISION_SUPPRESSED)
                .content("")
                .subject(subject);

        assertThatNoException()
                .isThrownBy(() -> publisherInstance.inform(notification, createConfig()));
    }

    private static Component createComponent(final Project project) {
        final var component = new Component();
        component.setProject(project);
        component.setUuid(UUID.fromString("94f87321-a5d1-4c2f-b2fe-95165debebc6"));
        component.setName("componentName");
        component.setVersion("componentVersion");
        return component;
    }

    private static Project createProject() {
        final var projectTag1 = new Tag();
        projectTag1.setName("tag1");
        final var projectTag2 = new Tag();
        projectTag2.setName("tag2");

        final var project = new Project();
        project.setUuid(UUID.fromString("c9c9539a-e381-4b36-ac52-6a7ab83b2c95"));
        project.setName("projectName");
        project.setVersion("projectVersion");
        project.setDescription("projectDescription");
        project.setPurl("pkg:maven/org.acme/projectName@projectVersion");
        project.setTags(List.of(projectTag1, projectTag2));
        return project;
    }

    private static Vulnerability createVulnerability() {
        final var alias = new org.dependencytrack.model.VulnerabilityAlias();
        alias.setInternalId("INT-001");
        alias.setOsvId("OSV-001");

        final var vuln = new org.dependencytrack.model.Vulnerability();
        vuln.setUuid(UUID.fromString("bccec5d5-ec21-4958-b3e8-22a7a866a05a"));
        vuln.setVulnId("INT-001");
        vuln.setSource(org.dependencytrack.model.Vulnerability.Source.INTERNAL);
        vuln.setAliases(List.of(alias));
        vuln.setTitle("vulnerabilityTitle");
        vuln.setSubTitle("vulnerabilitySubTitle");
        vuln.setDescription("vulnerabilityDescription");
        vuln.setRecommendation("vulnerabilityRecommendation");
        vuln.setCvssV2BaseScore(BigDecimal.valueOf(5.5));
        vuln.setCvssV3BaseScore(BigDecimal.valueOf(6.6));
        vuln.setOwaspRRLikelihoodScore(BigDecimal.valueOf(1.1));
        vuln.setOwaspRRTechnicalImpactScore(BigDecimal.valueOf(2.2));
        vuln.setOwaspRRBusinessImpactScore(BigDecimal.valueOf(3.3));
        vuln.setCwes(List.of(666, 777));
        return vuln;
    }

    private static Analysis createAnalysis(final Component component, final Vulnerability vuln) {
        final var analysis = new Analysis();
        analysis.setComponent(component);
        analysis.setVulnerability(vuln);
        analysis.setAnalysisState(AnalysisState.FALSE_POSITIVE);
        analysis.setSuppressed(true);
        return analysis;
    }

    private JsonObject createConfig() throws Exception {
        return Json.createObjectBuilder()
                .add(Publisher.CONFIG_TEMPLATE_MIME_TYPE_KEY, publisher.getTemplateMimeType())
                .add(Publisher.CONFIG_TEMPLATE_KEY, IOUtils.resourceToString(publisher.getPublisherTemplateFile(), UTF_8))
                .addAll(extraConfig())
                .build();
    }

    JsonObjectBuilder extraConfig() {
        return Json.createObjectBuilder();
    }

}
