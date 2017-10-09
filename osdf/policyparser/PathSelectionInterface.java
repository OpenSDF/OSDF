/*
 * Copyright 2017-present Open Networking Foundation
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

package org.onosproject.incubator.net.osdf.policyparser;

import org.onosproject.incubator.net.osdf.policies.DefaultPolicy;
import org.onosproject.net.DefaultPath;
import org.onosproject.net.Path;
import org.onosproject.net.PortNumber;
import org.onosproject.net.packet.InboundPacket;

import java.util.List;
import java.util.Set;

/**
 * An interface for path selection algorithms.
 */
public interface PathSelectionInterface {
    Path pickBestPossiblePath(Set<Path> paths,
                              PortNumber notToPort,
                              DefaultPolicy policy);

    Path pickRandomPath(Set<Path> paths,
                        DefaultPolicy policy);

    Path pickPathOnDemand(Set<Path> paths,
                          PortNumber notToPort,
                          DefaultPolicy policy,
                          DefaultPath endToEndPath);

    Path getEndtoEndPath(Set<Path> endToEndPaths,
                         DefaultPolicy policy);

    PathSelectionAlgos getPathSelectionAlgo(String pathSelectionAlgo);

    Path pickEcmpBasedPath(List<Path> paths,
                           DefaultPolicy policy,
                           InboundPacket pkt);
}
