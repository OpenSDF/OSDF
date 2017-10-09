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

/**
 * An enum data structure for well known application ports.
 */
public enum ApplicationPorts {

    /**
     * FTP port.
     */
    FTPDataPort(20),
    /**
     * HTTP port.
     */
    HTTPPort(80),
    /**
     * VOID port.
     */
    VOIPPort(3784),
    /**
     * TFTP port.
     */
    TFTPPort(69),
    /**
     * PING port.
     */
    PING(0),
    /**
     * Video streaming port.
     */
    VIDEO_STREAMING(8080);


    /**
     * Application port.
     */
    private int appPort;

    /**
     * Sets application port.
     *
     * @param appPort Application port
     */
    ApplicationPorts(int appPort) {
        this.appPort = appPort;


    }

    /**
     * Returns an application port.
     *
     * @return Application port
     */
    public int getApplicationPort() {

        return appPort;
    }
}
