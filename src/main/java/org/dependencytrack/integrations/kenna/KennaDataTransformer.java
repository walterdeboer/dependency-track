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
package org.dependencytrack.integrations.kenna;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.collections4.CollectionUtils;
import org.dependencytrack.common.Jackson;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.DateUtil;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Transforms Dependency-Track findings into Kenna Data Importer (KDI) format.
 */
public class KennaDataTransformer {

    private static final String SCANNER_TYPE = "Dependency-Track";
    private final QueryManager qm;
    private final Map<String, Vulnerability> portfolioVulnerabilities = new HashMap<>();
    private final ArrayNode assets = Jackson.newArray();
    private final ArrayNode vulnDefs = Jackson.newArray();

    KennaDataTransformer(final QueryManager qm) {
        this.qm = qm;
    }

    /**
     * Create the root-level JSON object. Requires projects to have been processed first.
     */
    public JsonNode generate() {
        // Creates the reference array of vulnerability definitions based on the vulnerabilities identified.
        // Using a Map to prevent duplicates based on the key.
        for (final Map.Entry<String, Vulnerability> entry : portfolioVulnerabilities.entrySet()) {
            vulnDefs.add(generateKdiVulnDef(entry.getValue()));
        }
        // Create the root-level JSON object
        final ObjectNode root = Jackson.newObject();
        root.put("skip_autoclose", false);
        root.set("assets", assets);
        root.set("vuln_defs", vulnDefs);
        return root;
    }

    public void process(final Project project, final String externalId) {
        final ObjectNode kdiAsset = generateKdiAsset(project, externalId);
        final ArrayNode vulns = Jackson.newArray();
        final List<Finding> findings = qm.getFindings(project);
        for (final Finding finding: findings) {
            final Map analysis = finding.getAnalysis();
            final Object suppressed = finding.getAnalysis().get("isSuppressed");
            if (suppressed instanceof Boolean) {
                final boolean isSuppressed = (Boolean)analysis.get("isSuppressed");
                if (isSuppressed) {
                    continue;
                }
            }
            final Vulnerability vulnerability = qm.getObjectByUuid(Vulnerability.class, (String)finding.getVulnerability().get("uuid"));
            //final Component component = qm.getObjectByUuid(Component.class, (String)finding.getComponent().get("uuid"));
            final String stateString = (String)finding.getAnalysis().get("state");
            final AnalysisState analysisState = (stateString != null) ? AnalysisState.valueOf(stateString) : AnalysisState.NOT_SET;
            final JsonNode kdiVuln = generateKdiVuln(vulnerability, analysisState);
            vulns.add(kdiVuln);
            portfolioVulnerabilities.put(generateScannerIdentifier(vulnerability), vulnerability);
        }
        kdiAsset.set("vulns", vulns);
        assets.add(kdiAsset);
    }

    /**
     * The scanner identifier is scoped to be unique to just the scanner (Dependency-Track). Therefore
     * we want to use a combination of SOURCE and VULN_ID to provide a consistent identifier across one
     * or more instances of Dependency-Track.
     */
    private String generateScannerIdentifier(final Vulnerability vulnerability) {
        return vulnerability.getSource() + "-" + vulnerability.getVulnId();
    }

    /**
     * Generates a KDI asset object.
     */
    private ObjectNode generateKdiAsset(final Project project, final String externalId) {
        final ObjectNode asset = Jackson.newObject();
        final String application = (project.getVersion() == null) ? project.getName() : project.getName() + " " + project.getVersion();
        asset.put("application", application);
        asset.put("external_id", externalId);
        // If the project has tags, add them to the KDI
        final List<Tag> tags = project.getTags();
        if (CollectionUtils.isNotEmpty(tags)) {
            final var tagArray = Jackson.newArray();
            for (final Tag tag: tags) {
                tagArray.add(tag.getName());
            }
            asset.put("tags", tagArray);
        }
        return asset;
    }

    /**
     * Generates a KDI vulnerability object which will be assigned to an asset and which will reference a KDI
     * vulnerability definition.
     */
    private JsonNode generateKdiVuln(final Vulnerability vulnerability, final AnalysisState analysisState) {
        final ObjectNode vuln = Jackson.newObject();
        vuln.put("scanner_type", SCANNER_TYPE);
        vuln.put("scanner_identifier", generateScannerIdentifier(vulnerability));
        vuln.put("last_seen_at", DateUtil.toISO8601(new Date()));
        // Update Kenna 'status' with the analysis state
        // Based on the analysis state, set the status in Kenna.
        // Valid values are: open, closed, false_positive, risk_accepted
        if (AnalysisState.FALSE_POSITIVE == analysisState) {
            vuln.put("status", "false_positive");
        } else if (AnalysisState.NOT_AFFECTED == analysisState) {
            vuln.put("status", "risk_accepted");
        } else {
            vuln.put("status", "open");
        }
        // Set the vulnerability scores (severity)
        if (vulnerability.getSeverity() != null) {
            final Severity severity = vulnerability.getSeverity();
            // scanner_score is on a scale of 0 - 10
            // override_score is on a scale of 0 - 100
            int scannerScore = 0;
            if (Severity.CRITICAL == severity) {
                scannerScore = 9;
            } else if (Severity.HIGH == severity) {
                scannerScore = 7;
            } else if (Severity.MEDIUM == severity) {
                scannerScore = 5;
            } else if (Severity.LOW == severity) {
                scannerScore = 3;
            }
            vuln.put("scanner_score", scannerScore);
            if (! Vulnerability.Source.NVD.name().equals(vulnerability.getSource())) {
                // If the vulnerability is not a CVE, then we need to override the score
                // to force Kenna to use this, otherwise the score will be 0.
                vuln.put("override_score", scannerScore * 10);
            }
        }
        return vuln;
    }

    /**
     * Generates a vulnerability definition that provides detail about the vulnerability assigned to the asset.
     */
    private JsonNode generateKdiVulnDef(final Vulnerability vulnerability) {
        final ObjectNode vulnDef = Jackson.newObject();
        vulnDef.put("scanner_type", SCANNER_TYPE);
        vulnDef.put("scanner_identifier", generateScannerIdentifier(vulnerability));
        if (vulnerability.getVulnId().startsWith("CVE-")) {
            vulnDef.put("cve_identifiers", vulnerability.getVulnId());
        }
        if (vulnerability.getCwes() != null) {
            vulnDef.put("cwe_identifier", "CWE-" + vulnerability.getCwes().get(0));
        }
        if (vulnerability.getTitle() != null) {
            vulnDef.put("name", vulnerability.getTitle());
        } else {
            vulnDef.put("name", vulnerability.getVulnId() + " (source: " + vulnerability.getSource() + ")");
        }
        if (vulnerability.getDescription() != null) {
            vulnDef.put("description", vulnerability.getDescription());
        }
        if (vulnerability.getDescription() != null) {
            vulnDef.put("solution", vulnerability.getRecommendation());
        }
        return vulnDef;
    }
}
