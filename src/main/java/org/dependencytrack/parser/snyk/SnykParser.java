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
package org.dependencytrack.parser.snyk;

import static org.dependencytrack.util.JsonUtil.jsonStringToTimestamp;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.common.Jackson;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Cwe;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.SnykCvssSource;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.parser.snyk.model.SnykError;
import org.dependencytrack.persistence.QueryManager;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;

import alpine.common.logging.Logger;
import alpine.model.ConfigProperty;

public class SnykParser {

    private static final Logger LOGGER = Logger.getLogger(SnykParser.class);

    public Vulnerability parse(ArrayNode data, QueryManager qm, String purl, int count) {
        Vulnerability synchronizedVulnerability = new Vulnerability();
        Vulnerability vulnerability = new Vulnerability();
        List<VulnerableSoftware> vsList = new ArrayList<>();
        vulnerability.setSource(Vulnerability.Source.SNYK);
        // get the id of the data record (vulnerability)
        vulnerability.setVulnId(Jackson.optString(Jackson.optNode(data, count), "id"));
        final JsonNode vulnAttributes = Jackson.optNode(Jackson.optNode(data, count), "attributes");
        if (vulnAttributes != null && Jackson.optString(vulnAttributes, "type").equalsIgnoreCase("package_vulnerability")) {
            // get the references of the data record (vulnerability)
            final JsonNode slots = Jackson.optNode(vulnAttributes, "slots");
            if (slots != null && Jackson.optArray(slots, "references") != null) {
                vulnerability.setReferences(addReferences(slots));
            }
            vulnerability.setTitle(Jackson.optString(vulnAttributes,"title"));
            vulnerability.setDescription(Jackson.optString(vulnAttributes,"description"));
            vulnerability.setCreated(Date.from(jsonStringToTimestamp(Jackson.optString(vulnAttributes,"created_at")).toInstant()));
            vulnerability.setUpdated(Date.from(jsonStringToTimestamp(Jackson.optString(vulnAttributes,"updated_at")).toInstant()));
            final ArrayNode problems = Jackson.optArray(vulnAttributes, "problems");
            if (problems != null) {
                vulnerability.setAliases(computeAliases(vulnerability, qm, problems));
            }
            final ArrayNode cvssArray = Jackson.optArray(vulnAttributes, "severities");
            vulnerability = cvssArray != null ? setCvssScore(cvssArray, vulnerability) : vulnerability;
            ArrayNode coordinates = Jackson.optArray(vulnAttributes, "coordinates");
            if (coordinates != null) {

                for (int countCoordinates = 0; countCoordinates < coordinates.size(); countCoordinates++) {
                    ArrayNode representation = Jackson.optArray(coordinates.get(countCoordinates), "representation");
                    if ((representation.size() == 1 && "*".equals(representation.get(0).asText()))) {
                        LOGGER.debug("Range only contains *. Will not compute vulnerable software for this range. Purl is: " + purl);
                    } else {
                        vsList = parseVersionRanges(qm, purl, representation);
                    }
                }
            }
            final List<VulnerableSoftware> vsListOld = qm.detach(qm.getVulnerableSoftwareByVulnId(vulnerability.getSource(), vulnerability.getVulnId()));
            synchronizedVulnerability = qm.synchronizeVulnerability(vulnerability, false);
            qm.persist(vsList);
            qm.updateAffectedVersionAttributions(synchronizedVulnerability, vsList, Vulnerability.Source.SNYK);
            vsList = qm.reconcileVulnerableSoftware(synchronizedVulnerability, vsListOld, vsList, Vulnerability.Source.SNYK);
            synchronizedVulnerability.setVulnerableSoftware(vsList);
            qm.persist(synchronizedVulnerability);
        }
        return synchronizedVulnerability;
    }

    public List<SnykError> parseErrors(final JsonNode jsonResponse) {
        if (jsonResponse == null || !jsonResponse.fields().hasNext()) {
            return Collections.emptyList();
        }

        final ArrayNode errorsArray = Jackson.optArray(jsonResponse, "errors");
        if (errorsArray == null) {
            return Collections.emptyList();
        }

        final var errors = new ArrayList<SnykError>();
        for (int i = 0; i < errorsArray.size(); i++) {
            final JsonNode errorObject = Jackson.optNode(errorsArray, i);
            if (errorObject == null) {
                continue;
            }

            errors.add(new SnykError(
                    Jackson.optString(errorObject,"code"),
                    Jackson.optString(errorObject,"title"),
                    Jackson.optString(errorObject,"detail")
            ));
        }

        return errors;
    }

    public List<VulnerabilityAlias> computeAliases(Vulnerability vulnerability, QueryManager qm, ArrayNode problems) {
        List<VulnerabilityAlias> vulnerabilityAliasList = new ArrayList<>();
        for (int i = 0; i < problems.size(); i++) {
            final JsonNode problem = Jackson.optNode(problems, i);
            String source = Jackson.optString(problem,"source");
            String id = Jackson.optString(problem,"id");
            // CWE
            if (source.equalsIgnoreCase("CWE")) {
                final Cwe cwe = CweResolver.getInstance().resolve(qm, id);
                if (cwe != null) {
                    vulnerability.addCwe(cwe);
                }
            }
            // CVE alias
            else if (source.equalsIgnoreCase("CVE")) {
                final VulnerabilityAlias vulnerabilityAlias = new VulnerabilityAlias();
                vulnerabilityAlias.setSnykId(vulnerability.getVulnId());
                vulnerabilityAlias.setCveId(id);
                qm.synchronizeVulnerabilityAlias(vulnerabilityAlias);
                vulnerabilityAliasList.add(vulnerabilityAlias);
            }
            // Github alias
            else if (source.equalsIgnoreCase("GHSA")) {
                final VulnerabilityAlias vulnerabilityAlias = new VulnerabilityAlias();
                vulnerabilityAlias.setSnykId(vulnerability.getVulnId());
                vulnerabilityAlias.setGhsaId(id);
                qm.synchronizeVulnerabilityAlias(vulnerabilityAlias);
                vulnerabilityAliasList.add(vulnerabilityAlias);
            }
        }
        return vulnerabilityAliasList;
    }

    public Vulnerability setCvssScore(ArrayNode cvssArray, Vulnerability vulnerability) {
        JsonNode cvss = selectCvssObjectBasedOnSource(cvssArray);
        if (cvss != null) {
            String severity = Jackson.optString(cvss,"level");
            if (severity != null) {
                if (severity.equalsIgnoreCase("CRITICAL")) {
                    vulnerability.setSeverity(Severity.CRITICAL);
                } else if (severity.equalsIgnoreCase("HIGH")) {
                    vulnerability.setSeverity(Severity.HIGH);
                } else if (severity.equalsIgnoreCase("MEDIUM")) {
                    vulnerability.setSeverity(Severity.MEDIUM);
                } else if (severity.equalsIgnoreCase("LOW")) {
                    vulnerability.setSeverity(Severity.LOW);
                } else {
                    vulnerability.setSeverity(Severity.UNASSIGNED);
                }
            }
            vulnerability.setCvssV3Vector(Jackson.optString(cvss,"vector"));
            final String cvssScore = Jackson.optString(cvss,"score");
            if (cvssScore != null) {
                vulnerability.setCvssV3BaseScore(BigDecimal.valueOf(Double.parseDouble(cvssScore)));
            }
        }
        return vulnerability;
    }

    public String addReferences(JsonNode slots) {
        final ArrayNode links = Jackson.optArray(slots, "references");
        final StringBuilder sb = new StringBuilder();
        for (int linkCount = 0; linkCount < links.size(); linkCount++) {
            final JsonNode link = links.get(linkCount);
            String reference = Jackson.optString(link,"url");
            if (reference != null) {
                sb.append("* [").append(reference).append("](").append(reference).append(")\n");
            }
        }
        return sb.toString();
    }

    public JsonNode selectCvssObjectBasedOnSource(ArrayNode cvssArray) {

        String cvssSourceHigh = getSnykCvssConfig(ConfigPropertyConstants.SCANNER_SNYK_CVSS_SOURCE);
        String cvssSourceLow = cvssSourceHigh.equalsIgnoreCase(SnykCvssSource.NVD.toString()) ? SnykCvssSource.SNYK.toString() : SnykCvssSource.NVD.toString();
        JsonNode cvss = Jackson.optNode(cvssArray, 0);
        if (cvssArray.size() > 1) {
            for (int i = 0; i < cvssArray.size(); i++) {
                final JsonNode cvssObject = Jackson.optNode(cvssArray, i);
                String source = Jackson.optString(cvssObject,"source");
                String vector = Jackson.optString(cvssObject,"vector");
                String score = Jackson.optString(cvssObject,"score");
                if (!StringUtils.isBlank(source) && !StringUtils.isBlank(vector) && !StringUtils.isBlank(score)) {
                    if (source.equalsIgnoreCase(cvssSourceHigh)) {
                        return cvssObject;
                    }
                    if (source.equalsIgnoreCase(cvssSourceLow)) {
                        cvss = cvssObject;
                    } else {
                        if (cvss != null && !Jackson.optString(cvss,"source").equalsIgnoreCase(cvssSourceLow)) {
                            cvss = cvssObject;
                        }
                    }
                }
            }
        }
        return cvss;
    }

    public List<VulnerableSoftware> parseVersionRanges(final QueryManager qm, final String purl, final ArrayNode ranges) {

        List<VulnerableSoftware> vulnerableSoftwares = new ArrayList<>();
        if (purl == null) {
            LOGGER.debug("No PURL provided - skipping");
            return Collections.emptyList();
        }

        final PackageURL packageURL;
        try {
            packageURL = new PackageURL(purl);
        } catch (MalformedPackageURLException ex) {
            LOGGER.debug("Invalid PURL  " + purl + " - skipping", ex);
            return Collections.emptyList();
        }
        for (int i = 0; i < ranges.size(); i++) {

            String range = Jackson.optString(ranges, i);
            String versionStartIncluding = null;
            String versionStartExcluding = null;
            String versionEndIncluding = null;
            String versionEndExcluding = null;

            final String[] parts;

            if (range.contains(",")) {
                parts = Arrays.stream(range.split(",")).map(String::trim).toArray(String[]::new);
            } else {
                parts = Arrays.stream(range.split(" ")).map(String::trim).toArray(String[]::new);
            }
            for (String part : parts) {
                if (part.startsWith(">=") || part.startsWith("[")) {
                    versionStartIncluding = part.replace(">=", "").replace("[", "").trim();
                    if (versionStartIncluding.length() == 0 || versionStartIncluding.contains("*")) {
                        versionStartIncluding = null;
                    }
                } else if (part.startsWith(">") || part.startsWith("(")) {
                    versionStartExcluding = part.replace(">", "").replace("(", "").trim();
                    if (versionStartExcluding.length() == 0 || versionStartExcluding.contains("*")) {
                        versionStartIncluding = null;
                    }
                } else if (part.startsWith("<=") || part.endsWith("]")) {
                    versionEndIncluding = part.replace("<=", "").replace("]", "").trim();
                } else if (part.startsWith("<") || part.endsWith(")")) {
                    versionEndExcluding = part.replace("<", "").replace(")", "").trim();
                    if (versionEndExcluding.length() == 0 || versionEndExcluding.contains("*")) {
                        versionStartIncluding = null;
                    }
                } else if (part.startsWith("=")) {
                    versionStartIncluding = part.replace("=", "").trim();
                    versionEndIncluding = part.replace("=", "").trim();
                    if (versionStartIncluding.length() == 0 || versionStartIncluding.contains("*")) {
                        versionStartIncluding = null;
                    }
                    if (versionEndIncluding.length() == 0 || versionEndIncluding.contains("*")) {
                        versionStartIncluding = null;
                    }
                } else { //since we are not able to parse specific range, we do not want to end up with false positives and therefore this part will be skipped from being saved to db.
                    LOGGER.debug("Range not definite. Not saving this vulnerable software information. The purl was: "+purl);
                }
            }

            //check for a numeric definite version range
            if ((versionStartIncluding != null && versionEndIncluding != null) || (versionStartIncluding != null && versionEndExcluding != null) || (versionStartExcluding != null && versionEndIncluding != null) || (versionStartExcluding != null && versionEndExcluding != null)) {
                VulnerableSoftware vs = qm.getVulnerableSoftwareByPurl(packageURL.getType(), packageURL.getNamespace(), packageURL.getName(), versionEndExcluding, versionEndIncluding, versionStartExcluding, versionStartIncluding);
                if (vs == null) {
                    vs = new VulnerableSoftware();
                    vs.setVulnerable(true);
                    vs.setPurlType(packageURL.getType());
                    vs.setPurlNamespace(packageURL.getNamespace());
                    vs.setPurlName(packageURL.getName());
                    vs.setVersion(packageURL.getVersion());
                    vs.setVersionStartIncluding(versionStartIncluding);
                    vs.setVersionStartExcluding(versionStartExcluding);
                    vs.setVersionEndIncluding(versionEndIncluding);
                    vs.setVersionEndExcluding(versionEndExcluding);
                }
                vulnerableSoftwares.add(vs);
            } else {
                LOGGER.debug("Range not definite. Not saving this vulnerable software information. The purl was: "+purl);
            }
        }
        return vulnerableSoftwares;
    }

    public String getSnykCvssConfig(ConfigPropertyConstants scannerSnykCvssSource) {

        try (QueryManager qm = new QueryManager()) {
            final ConfigProperty property = qm.getConfigProperty(scannerSnykCvssSource.getGroupName(), scannerSnykCvssSource.getPropertyName());
            if (property != null && ConfigProperty.PropertyType.STRING == property.getPropertyType()) {
                return property.getPropertyValue();
            }
        }
        return scannerSnykCvssSource.getDefaultPropertyValue();
    }
}
