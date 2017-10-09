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

package org.onosproject.incubator.net.osdf.applicationinfo;

import org.onosproject.incubator.net.osdf.transportprotocolinfo.TransportProtocols;

/**
 * An enum data structure for different types of applications.
 */
public enum ApplicationTypes {

    /**
     * Hyper Text Transfer Protocol (HTTP).
     */
    WEB(ApplicationPorts.HTTPPort,
            TransportProtocols.TCPv4,
            TrafficClasses.BEST_EFFORT),
    /**
     * File Transfer Protocol (FTP).
     */
    FTP(ApplicationPorts.FTPDataPort,
            TransportProtocols.TCPv4,
            TrafficClasses.BEST_EFFORT),
    /**
     * Voice Over IP (VOIP).
     */
    VOIP(ApplicationPorts.VOIPPort,
            TransportProtocols.UDPv4,
            TrafficClasses.REAL_TIME),
    /**
     * Trivial file transfer protocol (TFTP).
     */
    TFTP(ApplicationPorts.TFTPPort,
            TransportProtocols.TCPv4,
            TrafficClasses.BEST_EFFORT),

    /**
     * PING application.
     */
    PING(ApplicationPorts.PING,
            TransportProtocols.ICMPv4,
            TrafficClasses.BEST_EFFORT),
    /**
     * Video streaming application.
     */
    VIDEO_STREAMING(ApplicationPorts.VIDEO_STREAMING,
            TransportProtocols.TCPv4,
            TrafficClasses.REAL_TIME);

    private TrafficClasses trafficClass;
    private ApplicationPorts applicationPort;
    private TransportProtocols transportProtocol;

    /**
     * Defines an application type.
     *
     * @param applicationPort   application port
     * @param transportProtocol transport protocol
     * @param trafficClass      data traffic class
     */
    ApplicationTypes(ApplicationPorts applicationPort,
                     TransportProtocols transportProtocol,
                     TrafficClasses trafficClass) {

        this.applicationPort = applicationPort;
        this.transportProtocol = transportProtocol;
        this.trafficClass = trafficClass;

    }


    /**
     * Returns an application port.
     *
     * @return Application port
     */
    public ApplicationPorts getApplicationPort() {
        return applicationPort;

    }

    /**
     * Returns the transport protocol type.
     *
     * @return transport protocol
     */
    public TransportProtocols getTransportProtocol() {
        return transportProtocol;
    }

    /**
     * Returns the traffic class.
     *
     * @return traffic class
     */
    public TrafficClasses getTrafficClass() {
        return trafficClass;
    }


}




