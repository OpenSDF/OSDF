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

import org.onosproject.incubator.net.osdf.applicationinfo.ApplicationTypes;
import org.onosproject.incubator.net.osdf.applicationinfo.TrafficClasses;
import org.onosproject.net.flow.criteria.Criterion;

import java.util.Set;

/**
 * A default implementation of data traffic profiles.
 */
public class DefaultTrafficProfile extends TrafficProfile {

    private TrafficClasses trafficClass;
    private ApplicationTypes applicationType;
    private Set<Criterion> criteriaSet;


    /**
     * Default Constructor.
     */
    protected DefaultTrafficProfile() {
        super();
        this.criteriaSet = null;
        this.applicationType = null;
        this.trafficClass = null;
    }

    /**
     * Creates a traffic profile with a given name and a set of criteria.
     *
     * @param trafficProfileId traffic profile id
     * @param criteriaSet      a set of low level criteria
     * @param applicationType  application type
     * @param trafficClasses   traffic class
     */
    protected DefaultTrafficProfile(DefaultTrafficProfileId trafficProfileId,
                                    Set<Criterion> criteriaSet,
                                    ApplicationTypes applicationType,
                                    TrafficClasses trafficClasses) {
        super(trafficProfileId);
        this.criteriaSet = criteriaSet;
        this.applicationType = applicationType;
        this.trafficClass = trafficClasses;


    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Returns a set of criteria.
     *
     * @return criteriaSet
     */

    public Set<Criterion> getCriteriaSet() {
        return criteriaSet;
    }

    /**
     * Returns application type.
     *
     * @return applicationType
     */

    public ApplicationTypes getApplicationType() {
        return applicationType;
    }

    /**
     * Returns traffic class.
     *
     * @return traffic class
     */
    public TrafficClasses getTrafficClasses() {
        return trafficClass;
    }

    public static class Builder extends TrafficProfile.Builder {

        protected Set<Criterion> criteriaSet;
        protected ApplicationTypes applicationType;
        protected TrafficClasses trafficClass;

        /**
         * Creates an empty builder.
         */
        protected Builder() {

        }

        /**
         * @param trafficProfileId traffic profile id
         * @return traffic profile id builder
         */
        @Override
        public Builder trafficProfileId(DefaultTrafficProfileId trafficProfileId) {
            return (Builder) super.trafficProfileId(trafficProfileId);
        }

        /**
         * Sets a criteria set for the traffic profile.
         *
         * @param criterionSet a set of low level criteria
         * @return this builder
         */

        public Builder criteriaSet(Set<Criterion> criterionSet) {

            this.criteriaSet = criterionSet;
            return this;
        }

        /**
         * Sets an application type for the traffic profile.
         *
         * @param applicationType type of application
         * @return this builder
         */
        public Builder applicationType(ApplicationTypes applicationType) {
            this.applicationType = applicationType;
            return this;
        }

        /**
         * Builds a traffic class.
         *
         * @param trafficClass traffic class
         * @return this builder
         */
        public Builder trafficClass(TrafficClasses trafficClass) {
            this.trafficClass = trafficClass;
            return this;
        }

        /**
         * Builds a default traffic profile instance.
         *
         * @return default traffic profile instance
         */
        public DefaultTrafficProfile build() {
            return new DefaultTrafficProfile(trafficProfileId, criteriaSet, applicationType, trafficClass);
        }

    }

}
