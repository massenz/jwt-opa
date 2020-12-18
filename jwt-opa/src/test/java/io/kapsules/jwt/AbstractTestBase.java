/*
 * Copyright (c) 2020 kapsules.io.  All rights reserved.
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

package io.kapsules.jwt;

import io.kapsules.jwt.configuration.JwtSecurityConfiguration;
import io.kapsules.jwt.configuration.KeyMaterialConfiguration;
import io.kapsules.jwt.configuration.OpaServerConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/**
 * <h3>AbstractTestBase</h3>
 *
 * <p>Base class for all test classes, used to group commonly-used annotations in a single place.
 *
 * @author M. Massenzio, 2020-12-14
 */
@SpringBootTest(classes = {
    OpaServerConfiguration.class,
    JwtSecurityConfiguration.class,
    KeyMaterialConfiguration.class,
    JwtOpa.class
})
@ActiveProfiles("test")
public abstract class AbstractTestBase {
}
