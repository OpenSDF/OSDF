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

package org.onosproject.incubator.net.osdf.transportprotocolinfo;

/**
 * An enum data structure for well known transport protocols.
 */
public enum TransportProtocols {
    /**
     * IPv4 TCP.
     */
    TCPv4(6),
    /**
     * IPv4 UDP.
     */
    UDPv4(17),

    /**
     * IPv6 TCP.
     */
    TCPv6(6),

    /**
     * IPv6 UDP.
     */
    UDPv6(17),

    /**
     * MPLS.
     */
    MPLS(137),

    /**
     * ICMP version 4.
     */
    ICMPv4(1);

    /**
     * Protocol number.
     */

    private int proto;

    /**
     * Sets protocol number for a transport protocol.
     *
     * @param proto protocol number
     */
    TransportProtocols(int proto) {
        this.proto = proto;
    }


    /**
     * Returns protocol number.
     *
     * @return protocol number.
     */

    public int getProto() {
        return proto;
    }

}
