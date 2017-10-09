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

package org.onosproject.incubator.net.osdf.interrouteconfigs;

import org.onlab.packet.IpAddress;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.MacAddress;

/**
 * Inter-route configuration interface.
 */
public interface InterRouteConfigurationService {
    String INTER_ROUTING_APP_ID = "org.onosproject.InterRouting";

    Class<InterRouteConfig> CONFIG_CLASS = InterRouteConfig.class;

    MacAddress getVirtualGatewayMacAddress();

    /**
     * Evaluates whether an IP address is a virtual gateway IP address.
     *
     * @param ipAddress the IP address to evaluate
     * @return true if the IP address is a virtual gateway address, otherwise false
     */
    boolean isVirtualGatewayIpAddress(IpAddress ipAddress);

    /**
     * Evaluates whether an IP address belongs to local SDN network.
     *
     * @param ipAddress the IP address to evaluate
     * @return true if the IP address belongs to local SDN network, otherwise false
     */
    boolean isIpAddressLocal(IpAddress ipAddress);

    /**
     * Evaluates whether an IP prefix belongs to local SDN network.
     *
     * @param ipPrefix the IP prefix to evaluate
     * @return true if the IP prefix belongs to local SDN network, otherwise false
     */

    boolean isIpPrefixLocal(IpPrefix ipPrefix);


    /**
     * Returns the region ID of a given IP prefix.
     *
     * @param ipPrefix ip prefix.
     * @return region ID.
     */
    String getRegion(IpPrefix ipPrefix);


    int getPrefixLen(IpPrefix ipPrefix);


}
