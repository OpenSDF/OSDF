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

package org.onosproject.incubator.net.osdf.trafficprofiles;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * An implementation of TrafficProfileId interface.
 */
public class DefaultTrafficProfileId implements TrafficProfileId {
    private static AtomicInteger uniqueId = new AtomicInteger();
    private final int profileId;
    private String profileName;

    /**
     * Creates a profile ID with given information.
     *
     * @param profileName name of a profile
     */
    public DefaultTrafficProfileId(String profileName) {

        this.profileId = uniqueId.getAndIncrement();
        this.profileName = profileName;

    }

    /**
     * Returns a profile Id.
     *
     * @return ProfileId
     */
    @Override
    public int getProfileId() {

        return profileId;
    }

    /**
     * Returns a profile name.
     *
     * @return ProfileName
     */
    @Override
    public String getProfileName() {

        return profileName;
    }
}
