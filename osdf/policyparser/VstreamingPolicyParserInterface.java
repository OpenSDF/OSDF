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

import org.onlab.packet.Ethernet;
import org.onosproject.incubator.net.osdf.policies.DefaultPolicy;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.packet.InboundPacket;

/**
 * Video Streaming Policy Parser Interface.
 */
public interface VstreamingPolicyParserInterface {
    /**
     * Traffic selector for routing video streaming traffic inside a region.
     *
     * @param pkt    Inbound packet
     * @param ethPkt Ethernet packet
     * @param policy a policy
     * @return traffic selector builder
     */
    TrafficSelector.Builder intraVideoStreamTrafficSelector(InboundPacket pkt,
                                                            Ethernet ethPkt,
                                                            DefaultPolicy policy);


    TrafficSelector.Builder interVideoStreamTrafficSelector(InboundPacket pkt,
                                                            Ethernet ethPkt,
                                                            DefaultPolicy policy);

}
