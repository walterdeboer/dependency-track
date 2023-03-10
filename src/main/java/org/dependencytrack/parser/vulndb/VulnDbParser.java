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
package org.dependencytrack.parser.vulndb;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.common.Jackson;
import org.dependencytrack.parser.vulndb.model.ApiObject;
import org.dependencytrack.parser.vulndb.model.Author;
import org.dependencytrack.parser.vulndb.model.Classification;
import org.dependencytrack.parser.vulndb.model.Cpe;
import org.dependencytrack.parser.vulndb.model.CvssV2Metric;
import org.dependencytrack.parser.vulndb.model.CvssV3Metric;
import org.dependencytrack.parser.vulndb.model.ExternalReference;
import org.dependencytrack.parser.vulndb.model.ExternalText;
import org.dependencytrack.parser.vulndb.model.NvdAdditionalInfo;
import org.dependencytrack.parser.vulndb.model.Product;
import org.dependencytrack.parser.vulndb.model.Results;
import org.dependencytrack.parser.vulndb.model.Status;
import org.dependencytrack.parser.vulndb.model.Vendor;
import org.dependencytrack.parser.vulndb.model.Version;
import org.dependencytrack.parser.vulndb.model.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;

/*
 * Model class needed by VulnDBAnalysis task. Class brought over from the vulndb-data-mirror repo:
 * <a href="https://github.com/stevespringett/vulndb-data-mirror">...</a>
 */
public class VulnDbParser {
    private static final Logger LOGGER = LoggerFactory.getLogger(VulnDbParser.class);

    public VulnDbParser() {
    }

    public Status parseStatus(JsonNode root) {
        LOGGER.debug("Parsing JSON node");
        Status status = new Status(Jackson.optString(root, "organization_name"), Jackson.optString(root, "user_name_requesting"),
                Jackson.optString(root, "user_email_address_requesting"),
                Jackson.optString(root, "subscription_end_date"),
                Jackson.optString(root, "number_of_api_calls_allowed_per_month"),
                Jackson.optString(root, "number_of_api_calls_made_this_month"),
                Jackson.optString(root, "vulndb_statistics"),
                root.toString()
        );
        return status;
    }

    public <T> Results<T> parse(Object jsonNode, Class<? extends ApiObject> apiObject) {
        LOGGER.debug("Parsing JSON node");

        final Results<T> results = new Results<>();
        JsonNode root;
        root = (JsonNode) jsonNode;
        results.setPage(root.get("current_page").asInt());
        results.setTotal(root.get("total_entries").asInt());
        results.setRawResults(jsonNode.toString());
        final ArrayNode rso = Jackson.asArray(root, "results");

        if (Product.class == apiObject) {
            results.setResults(parseProducts(rso));
        } else if (Vendor.class == apiObject) {
            results.setResults(parseVendors(rso));
        } else if (Version.class == apiObject) {
            results.setResults(parseVersions(rso));
        } else if (Vulnerability.class == apiObject) {
            results.setResults(parseVulnerabilities(rso));
        }
        return results;
    }

    public <T> Results<T> parse(final String jsonData, Class<? extends ApiObject> apiObject) {
        JsonNode result = Jackson.readString(jsonData);
        if (result instanceof JsonNode) {
            return this.parse((JsonNode) result, apiObject);
        } else {
            return this.parse((ArrayNode) result, apiObject);
        }
    }

    public <T> Results<T> parse(File file, Class<? extends ApiObject> apiObject) throws IOException {
        String jsonData = Files.readString(Paths.get(file.toURI()), Charset.defaultCharset());
        JsonNode result = Jackson.readString(jsonData);
        if (result instanceof JsonNode) {
            return this.parse((JsonNode) result, apiObject);
        } else {
            return this.parse((ArrayNode) result, apiObject);
        }
    }

    private List<Cpe> parseCpes(ArrayNode rso) {
        List<Cpe> cpes = null;
        if (rso != null) {
            cpes = new ArrayList();

            for (int i = 0; i < rso.size(); ++i) {
                JsonNode object = rso.get(i);
                Cpe cpe = new Cpe(StringUtils.trimToNull(Jackson.optString(object, "cpe")), StringUtils.trimToNull(Jackson.optString(object, "type")));
                cpes.add(cpe);
            }
        }

        return cpes;
    }

    private List<Product> parseProducts(ArrayNode rso) {
        List<Product> products = null;
        if (rso != null) {
            products = new ArrayList();

            for (int i = 0; i < rso.size(); ++i) {
                JsonNode object = rso.get(i);
                Product product = new Product(object.get("id").asInt(),
                        StringUtils.trimToNull(Jackson.optString(object, "name")),
                        this.parseVersions(Jackson.optArray(object, "versions")));
                products.add(product);
            }
        }

        return products;
    }

    private List<Vendor> parseVendors(ArrayNode rso) {
        List<Vendor> vendors = null;
        if (rso != null) {
            vendors = new ArrayList();

            for (int i = 0; i < rso.size(); ++i) {
                JsonNode object = rso.get(i);
                if (object.has("vendor")) {
                    JsonNode childObject = object.get("vendor");
                    Vendor vendor = this.parseVendor(childObject);
                    vendors.add(vendor);
                } else {
                    Vendor vendor = this.parseVendor(object);
                    vendors.add(vendor);
                }
            }
        }

        return vendors;
    }

    private Vendor parseVendor(JsonNode object) {
        Vendor vendor = new Vendor(object.get("id").asInt(),
                StringUtils.trimToNull(Jackson.optString(object, "name")),
                StringUtils.trimToNull(Jackson.optString(object, "short_name")),
                StringUtils.trimToNull(Jackson.optString(object, "vendor_url")),
                this.parseProducts(Jackson.optArray(object, "products")));
        return vendor;
    }

    private List<Version> parseVersions(ArrayNode rso) {
        List<Version> versions = null;
        if (rso != null) {
            versions = new ArrayList();

            for (int i = 0; i < rso.size(); ++i) {
                JsonNode object = rso.get(i);
                Version version = new Version(object.get("id").asInt(),
                        StringUtils.trimToNull(Jackson.optString(object, "name")),
                        Jackson.optBoolean(object, "affected"),
                        this.parseCpes(Jackson.optArray(object, "cpe")));
                versions.add(version);
            }
        }

        return versions;
    }

    private List<Vulnerability> parseVulnerabilities(ArrayNode rso) {
        List<Vulnerability> vulnerabilities = null;
        if (rso != null) {
            vulnerabilities = new ArrayList();

            for (int i = 0; i < rso.size(); ++i) {
                JsonNode object = rso.get(i);
                ArrayNode classifications = Jackson.optArray(object, "classifications");
                List<Classification> classificationList = new ArrayList<>();
                if (classifications != null) {
                    for (int j = 0; j < classifications.size(); ++j) {
                        JsonNode jso = classifications.get(j);
                        Classification classification = new Classification(jso.get("id").asInt(), StringUtils.trimToNull(Jackson.optString(jso, "name")), StringUtils.trimToNull(Jackson.optString(jso, "longname")), StringUtils.trimToNull(Jackson.optString(jso, "description")),
                                StringUtils.trimToNull(Jackson.optString(jso, "mediumtext")));
                        classificationList.add(classification);
                    }
                }

                ArrayNode authors = Jackson.optArray(object, "authors");
                List<Author> authorList = new ArrayList<>();
                if (authors != null) {
                    for (int j = 0; j < authors.size(); ++j) {
                        JsonNode jso = authors.get(j);
                        Author author = new Author(jso.get("id").asInt(), StringUtils.trimToNull(Jackson.optString(jso, "name")), StringUtils.trimToNull(Jackson.optString(jso, "company")),
                                StringUtils.trimToNull(Jackson.optString(jso, "email")),
                                StringUtils.trimToNull(Jackson.optString(jso, "company_url")),
                                StringUtils.trimToNull(Jackson.optString(jso, "country")));
                        authorList.add(author);
                    }
                }

                ArrayNode extRefs = Jackson.optArray(object, "ext_references");
                List<ExternalReference> externalReferenceList = new ArrayList<>();
                if (extRefs != null) {
                    for (int j = 0; j < extRefs.size(); ++j) {
                        JsonNode jso = extRefs.get(j);
                        ExternalReference externalReference = new ExternalReference(StringUtils.trimToNull(Jackson.optString(jso, "type")),
                                StringUtils.trimToNull(Jackson.optString(jso, "value")));
                        externalReferenceList.add(externalReference);
                    }
                }

                ArrayNode extTexts = Jackson.optArray(object, "ext_texts");
                List<ExternalText> externalTextList = new ArrayList<>();
                if (extTexts != null) {
                    for (int j = 0; j < extTexts.size(); ++j) {
                        JsonNode jso = extTexts.get(j);
                        ExternalText externalText = new ExternalText(StringUtils.trimToNull(Jackson.optString(jso, "type")),
                                StringUtils.trimToNull(Jackson.optString(jso, "value")));
                        externalTextList.add(externalText);
                    }
                }

                ArrayNode cvssv2Metrics = Jackson.optArray(object, "cvss_metrics");
                List<CvssV2Metric> cvssV2MetricList = new ArrayList<>();
                if (cvssv2Metrics != null) {
                    for (int j = 0; j < cvssv2Metrics.size(); ++j) {
                        JsonNode jso = cvssv2Metrics.get(j);
                        CvssV2Metric metric = new CvssV2Metric(jso.get("id").asInt(),
                                StringUtils.trimToNull(Jackson.optString(jso, "access_complexity")),
                                StringUtils.trimToNull(Jackson.optString(jso, "cve_id")),
                                StringUtils.trimToNull(Jackson.optString(jso, "source")),
                                StringUtils.trimToNull(Jackson.optString(jso, "availability_impact")),
                                StringUtils.trimToNull(Jackson.optString(jso, "confidentiality_impact")),
                                StringUtils.trimToNull(Jackson.optString(jso, "authentication")),
                                Jackson.optBigDecimal(jso, "calculated_cvss_base_score"),
                                StringUtils.trimToNull(Jackson.optString(jso, "generated_on")),
                                Jackson.optBigDecimal(jso, "score"),
                                StringUtils.trimToNull(Jackson.optString(jso, "access_vector")),
                                StringUtils.trimToNull(Jackson.optString(jso, "integrity_impact")));
                        cvssV2MetricList.add(metric);
                    }
                }

                ArrayNode cvssv3Metrics = Jackson.optArray(object, "cvss_version_three_metrics");
                List<CvssV3Metric> cvssV3MetricList = new ArrayList<>();
                if (cvssv3Metrics != null) {
                    for (int j = 0; j < cvssv3Metrics.size(); ++j) {
                        JsonNode jso = cvssv3Metrics.get(j);
                        CvssV3Metric metric = new CvssV3Metric(jso.get("id").asInt(),
                                StringUtils.trimToNull(Jackson.optString(jso, "attack_complexity")),
                                Jackson.optString(jso, "scope"),
                                Jackson.optString(jso, "attack_vector"),
                                StringUtils.trimToNull(Jackson.optString(jso, "availability_impact")),
                                Jackson.optBigDecimal(jso, "score"),
                                StringUtils.trimToNull(Jackson.optString(jso, "privileges_required")),
                                StringUtils.trimToNull(Jackson.optString(jso, "user_interaction")),
                                StringUtils.trimToNull(Jackson.optString(jso, "cve_id")),
                                StringUtils.trimToNull(Jackson.optString(jso, "source")),
                                StringUtils.trimToNull(Jackson.optString(jso, "confidentiality_impact")),
                                Jackson.optBigDecimal(jso, "calculated_cvss_base_score"),
                                StringUtils.trimToNull(Jackson.optString(jso, "generated_on")),
                                StringUtils.trimToNull(Jackson.optString(jso, "integrity_impact"))
                        );
                        cvssV3MetricList.add(metric);
                    }
                }

                ArrayNode nvdInfo = Jackson.optArray(object, "nvd_additional_information");
               // List<NvdAdditionalInfo> nvdAdditionalInfos = new ArrayList<>();
                NvdAdditionalInfo nvdAdditionalInfo = null;
                if (nvdInfo != null) {
//                    for (int j = 0; j < nvdInfo.size(); ++j) {
//                        JsonNode jso = nvdInfo.get(j);
//                        NvdAdditionalInfo nvdAdditionalInfo = new NvdAdditionalInfo(StringUtils.trimToNull(Jackson.optString(jso, "summary")),
//                                StringUtils.trimToNull(Jackson.optString(jso, "cwe_id")),
//                                StringUtils.trimToNull(Jackson.optString(jso, "cve_id")));
//                        nvdAdditionalInfos.add(nvdAdditionalInfo);
//                    }
                     nvdAdditionalInfo = new NvdAdditionalInfo(StringUtils.trimToNull(Jackson.optString(nvdInfo.get(nvdInfo.size() - 1), "summary")),
                            StringUtils.trimToNull(Jackson.optString(nvdInfo.get(nvdInfo.size() - 1), "cwe_id")),
                            StringUtils.trimToNull(Jackson.optString(nvdInfo.get(nvdInfo.size() - 1), "cve_id")));

                }

                ArrayNode vendors = Jackson.optArray(object, "vendors");
                Vulnerability vulnerability = new Vulnerability(object.get("vulndb_id").asInt(),
                        StringUtils.trimToNull(Jackson.optString(object, "title")),
                        StringUtils.trimToNull(Jackson.optString(object, "disclosure_date")),
                        StringUtils.trimToNull(Jackson.optString(object, "discovery_date")),
                        StringUtils.trimToNull(Jackson.optString(object, "exploit_publish_date")),
                        StringUtils.trimToNull(Jackson.optString(object, "keywords")),
                        StringUtils.trimToNull(Jackson.optString(object, "short_description")),
                        StringUtils.trimToNull(Jackson.optString(object, "description")),
                        StringUtils.trimToNull(Jackson.optString(object, "solution")),
                        StringUtils.trimToNull(Jackson.optString(object, "manual_notes")),
                        StringUtils.trimToNull(Jackson.optString(object, "t_description")),
                        StringUtils.trimToNull(Jackson.optString(object, "solution_date")),
                        StringUtils.trimToNull(Jackson.optString(object, "vendor_informed_date")),
                        StringUtils.trimToNull(Jackson.optString(object, "vendor_ack_date")),
                        StringUtils.trimToNull(Jackson.optString(object, "third_party_solution_date")),
                        classificationList,
                        authorList,
                        externalReferenceList,
                        externalTextList,
                        this.parseVendors(vendors),
                        cvssV2MetricList,
                        cvssV3MetricList,
                        nvdAdditionalInfo
                );
                vulnerabilities.add(vulnerability);
            }
        }

        return vulnerabilities;
    }
}
