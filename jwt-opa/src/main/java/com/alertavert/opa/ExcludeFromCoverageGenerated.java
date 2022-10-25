/*
 * Copyright (c) 2021 AlertAvert.com.  All rights reserved.
 * Author: Marco Massenzio (marco@alertavert.com)
 */
package com.alertavert.opa;

/**
 * Marker annotation for classes to be excluded by Jacoco test coverage report and rules.
 *
 * The naming is a bit contrived as Jacoco <strong>requires</strong> that the
 * {@literal Generated} string be present in the annotation; classes annotated
 * with {@link ExcludeFromCoverageGenerated} are <strong>not</strong> generated at all
 * (Lombok does annotate methods/classes with {@link lombok.Generated}).
 *
 * Typically classes annotated with this marker <em>SHOULD</em> only contain either
 * fairly trivial logic (e.g., configuration properties parsing and conversion) or access runtime
 * components (e.g., AWS) where testing would require extensive (and, ultimately, self-defeating)
 * mocking or real online services.
 *
 * <strong>USE WITH MODERATION</strong> and, most importantly, <strong>do not</strong> use it to
 * bypass the Code Coverage check.
 *
 * @author M. Massenzio, 2022-04-14
 */
public @interface ExcludeFromCoverageGenerated {
}
