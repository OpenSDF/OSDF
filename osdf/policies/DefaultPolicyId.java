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


import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.Service;
import org.onlab.osgi.DefaultServiceDirectory;
import org.onosproject.incubator.net.osdf.policystorage.PolicyService;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * An implementation of PolicyId interface.
 */
@Component(immediate = true)
@Service
public class DefaultPolicyId extends AbstractPolicyID implements PolicyIdInterface {

    private static AtomicInteger uniqueId = new AtomicInteger();
    //private final Logger log = getLogger(getClass().getName());
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected PolicyService policyService;
    private String policyName;
    private int policyId;

    @Activate
    public void activate() {
        //log.info("Started");

    }

    @Deactivate
    public void deactivate() {
        //log.info("Stopped");

    }


    /**
     * find a missing policy ID based on a set of existing policy IDs.
     *
     * @param array array of indexes
     * @param start starting index
     * @param end   ending index
     * @return a policy ID
     */
    private int findFirstMissing(List<Integer> array, int start, int end) {
        if (start > end) {
            return end + 1;
        }

        if (start != array.get(start)) {
            return start;
        }

        int mid = (start + end) / 2;

        // Left half has all elements from 0 to mid
        if (array.get(mid) == mid) {
            return findFirstMissing(array, mid + 1, end);
        }

        return findFirstMissing(array, start, mid);
    }

    /**
     * Creates a policy Id based on given policy name.
     *
     * @param policyName policy name
     */
    public void createPolicyId(String policyName) {
        this.policyName = policyName;
        policyService = DefaultServiceDirectory.getService(PolicyService.class);

        if (policyService.getCurrentPolicyMap().size() >= 0) {
            Set<DefaultPolicyId> policyIdSet = policyService.getCurrentPolicyMap().keySet();

            List<Integer> policyIdSetValues = new ArrayList<>();
            for (DefaultPolicyId policyId : policyIdSet) {
                policyIdSetValues.add(policyId.getPolicyId());
            }
            Collections.sort(policyIdSetValues);
            int missingNumber = findFirstMissing(policyIdSetValues, 0, policyIdSetValues.size() - 1);

            if (missingNumber == policyIdSetValues.size() + 1) {
                this.policyId = uniqueId.getAndIncrement();
            } else {
                this.policyId = missingNumber;
            }
        }


    }


    @Override
    /*
     * Returns a policyId.
     */
    public int getPolicyId() {

        return policyId;

    }

    @Override
    /*
      Returns a Policy name.
      @param PolicyName
     */
    public String getPolicyName() {
        return policyName;
    }


}
