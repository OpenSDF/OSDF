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

/**
 * Abstraction of high level traffic profiles.
 */
public abstract class TrafficProfile {


    private DefaultTrafficProfileId trafficProfileId;

    /**
     * Initialize traffic profile variables.
     */
    protected TrafficProfile() {
        trafficProfileId = null;

    }

    /**
     * Creates a new Traffic Profile with a given name.
     *
     * @param trafficProfileId an instance of traffic profile id
     */
    protected TrafficProfile(DefaultTrafficProfileId trafficProfileId) {
        this.trafficProfileId = trafficProfileId;

    }

    /**
     * Returns the id of a traffic profile.
     *
     * @return trafficProfileId
     */
    public DefaultTrafficProfileId getTrafficProfileId() {

        return trafficProfileId;
    }

    public abstract static class Builder {

        protected DefaultTrafficProfileId trafficProfileId;

        /**
         * Creates an empty builder.
         */
        protected Builder() {

        }

        /**
         * Returns a traffic profile ID builder.
         * Creates a new traffic Profile with a given profile name.
         *
         * @param trafficProfileId traffic profile id
         * @return this builder
         */
        public Builder trafficProfileId(DefaultTrafficProfileId trafficProfileId) {


            this.trafficProfileId = trafficProfileId;
            return this;

        }


    }

}
