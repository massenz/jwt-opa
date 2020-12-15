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
