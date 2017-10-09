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

package org.onosproject.incubator.net.osdf.policies;

import org.onosproject.incubator.net.osdf.policystorage.PolicyState;

/**
 * Abstraction of high Level network polices.
 */
public abstract class Policy {

    public static final int DEFAULT_POLICY_PRIORITY = 100;
    public static final int POLICY_MIN_PRIORITY = 1;
    public static final int POLICY_MAX_PRIORITY = (1 << 16) - 1;
    private final DefaultPolicyId policyId;
    private int priority;
    private PolicyState policyState;
    private int version;


    /**
     * Initialize Policy class variables.
     */

    protected Policy() {

        this.policyId = null;
        this.priority = DEFAULT_POLICY_PRIORITY;
        this.policyState = null;
        this.version = 0;
    }

    /**
     * Creates a new Policy.
     *
     * @param policyId    Policy identifier
     * @param priority    flow rule priority
     * @param policyState policy state
     * @param version     policy version
     */
    protected Policy(DefaultPolicyId policyId,
                     int priority,
                     PolicyState policyState,
                     int version
    ) {
        this.policyId = policyId;
        this.priority = priority;
        this.policyState = policyState;
        this.version = version;

    }

    /**
     * Returns the id of a Policy.
     *
     * @return policyId
     */

    public PolicyIdInterface getPolicyId() {
        return policyId;
    }

    /**
     * Returns the priority of a Policy.
     *
     * @return priority
     */

    public int getPriority() {
        return priority;
    }


    public PolicyState getPolicyState() {
        return policyState;

    }

    public int getVersion() {
        return version;
    }

    /**
     * Abstract builder for polices.
     */

    public abstract static class Builder {
        protected DefaultPolicyId policyId;
        protected int priority;
        protected PolicyState policyState;
        protected int version;

        /**
         * Creates a new empty builder.
         */
        protected Builder() {
        }

        /**
         * Sets the policy id for the policy.
         *
         * @param policyId policy identifier
         * @return this builder
         */

        public Builder policyId(DefaultPolicyId policyId) {
            this.policyId = policyId;
            return this;
        }

        /**
         * Sets the priority for the policy.
         *
         * @param priority priority of the policy
         * @return this builder
         */
        public Builder priority(int priority) {
            this.priority = priority;
            return this;
        }

        /**
         * Sets a policy state for the policy.
         *
         * @param policyState policy state
         * @return this builder
         */
        public Builder policyState(PolicyState policyState) {
            this.policyState = policyState;
            return this;
        }

        /**
         * Sets a version for the policy.
         *
         * @param version policy version
         * @return this builder
         */
        public Builder version(int version) {
            this.version = version;
            return this;
        }

    }


}
