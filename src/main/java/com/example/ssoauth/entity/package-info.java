/**
 * This package-info.java file contains the central Hibernate Filter Definition
 * for multi-tenancy. This @FilterDef is defined ONCE here and applied
 * to multiple entities (like User and SsoProviderConfig) using the @Filter annotation.
 */
@org.hibernate.annotations.FilterDef(
        name = "tenantFilter",
        parameters = @org.hibernate.annotations.ParamDef(name = "tenantId", type = Long.class)
)
package com.example.ssoauth.entity;