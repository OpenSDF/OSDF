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

package org.onosproject.cli.net.osdf;

import org.apache.karaf.shell.commands.Command;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.incubator.net.osdf.policies.DefaultPolicy;
import org.onosproject.incubator.net.osdf.policies.Policy;
import org.onosproject.incubator.net.osdf.policystorage.PolicyService;

import java.util.Iterator;

/**
 * List current network policies.
 */
@Command(scope = "onos", name = "lp",
        description = "List current network policies")
public class ListPoliciesCommand extends AbstractShellCommand {


    private static final String FMT =
            "id=%s, ProfileName=%s, priority=%s, app=%s,devicesList=%s, srcHostsList=%s " + "dstHostsList=%s" +
                    "srcRegion=%s,dstRegion=%s,action=%s,";

    @Override
    protected void execute() {
        PolicyService policyService;
        policyService = get(PolicyService.class);

        Iterator<Policy> policyIterator = policyService.getCurrentPolicies().iterator();

        while (policyIterator.hasNext()) {
            DefaultPolicy policy = (DefaultPolicy) policyIterator.next();
            print(FMT, policy.getPolicyId().getPolicyId(),
                    policy.getTrafficProfile().getTrafficProfileId().getProfileName(),
                    policy.getPriority(),
                    policy.getTrafficProfile().getApplicationType(),
                    policy.getDeviceList().toString(),
                    policy.getSrcHostsList().toString(),
                    policy.getDstHostsList().toString(),
                    policy.getSrcRegion().id().toString(),
                    policy.getDstRegion().id().toString(),
                    policy.getAction().toString());

        }


    }
}
