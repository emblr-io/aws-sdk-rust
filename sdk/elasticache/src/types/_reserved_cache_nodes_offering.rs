// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes all of the attributes of a reserved cache node offering.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ReservedCacheNodesOffering {
    /// <p>A unique identifier for the reserved cache node offering.</p>
    pub reserved_cache_nodes_offering_id: ::std::option::Option<::std::string::String>,
    /// <p>The cache node type for the reserved cache node.</p>
    /// <p>The following node types are supported by ElastiCache. Generally speaking, the current generation types provide more memory and computational power at lower cost when compared to their equivalent previous generation counterparts.</p>
    /// <ul>
    /// <li>
    /// <p>General purpose:</p>
    /// <ul>
    /// <li>
    /// <p>Current generation:</p>
    /// <p><b>M7g node types</b>: <code>cache.m7g.large</code>, <code>cache.m7g.xlarge</code>, <code>cache.m7g.2xlarge</code>, <code>cache.m7g.4xlarge</code>, <code>cache.m7g.8xlarge</code>, <code>cache.m7g.12xlarge</code>, <code>cache.m7g.16xlarge</code></p><note>
    /// <p>For region availability, see <a href="https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/CacheNodes.SupportedTypes.html#CacheNodes.SupportedTypesByRegion">Supported Node Types</a></p>
    /// </note>
    /// <p><b>M6g node types</b> (available only for Redis OSS engine version 5.0.6 onward and for Memcached engine version 1.5.16 onward): <code>cache.m6g.large</code>, <code>cache.m6g.xlarge</code>, <code>cache.m6g.2xlarge</code>, <code>cache.m6g.4xlarge</code>, <code>cache.m6g.8xlarge</code>, <code>cache.m6g.12xlarge</code>, <code>cache.m6g.16xlarge</code></p>
    /// <p><b>M5 node types:</b> <code>cache.m5.large</code>, <code>cache.m5.xlarge</code>, <code>cache.m5.2xlarge</code>, <code>cache.m5.4xlarge</code>, <code>cache.m5.12xlarge</code>, <code>cache.m5.24xlarge</code></p>
    /// <p><b>M4 node types:</b> <code>cache.m4.large</code>, <code>cache.m4.xlarge</code>, <code>cache.m4.2xlarge</code>, <code>cache.m4.4xlarge</code>, <code>cache.m4.10xlarge</code></p>
    /// <p><b>T4g node types</b> (available only for Redis OSS engine version 5.0.6 onward and Memcached engine version 1.5.16 onward): <code>cache.t4g.micro</code>, <code>cache.t4g.small</code>, <code>cache.t4g.medium</code></p>
    /// <p><b>T3 node types:</b> <code>cache.t3.micro</code>, <code>cache.t3.small</code>, <code>cache.t3.medium</code></p>
    /// <p><b>T2 node types:</b> <code>cache.t2.micro</code>, <code>cache.t2.small</code>, <code>cache.t2.medium</code></p></li>
    /// <li>
    /// <p>Previous generation: (not recommended. Existing clusters are still supported but creation of new clusters is not supported for these types.)</p>
    /// <p><b>T1 node types:</b> <code>cache.t1.micro</code></p>
    /// <p><b>M1 node types:</b> <code>cache.m1.small</code>, <code>cache.m1.medium</code>, <code>cache.m1.large</code>, <code>cache.m1.xlarge</code></p>
    /// <p><b>M3 node types:</b> <code>cache.m3.medium</code>, <code>cache.m3.large</code>, <code>cache.m3.xlarge</code>, <code>cache.m3.2xlarge</code></p></li>
    /// </ul></li>
    /// <li>
    /// <p>Compute optimized:</p>
    /// <ul>
    /// <li>
    /// <p>Previous generation: (not recommended. Existing clusters are still supported but creation of new clusters is not supported for these types.)</p>
    /// <p><b>C1 node types:</b> <code>cache.c1.xlarge</code></p></li>
    /// </ul></li>
    /// <li>
    /// <p>Memory optimized:</p>
    /// <ul>
    /// <li>
    /// <p>Current generation:</p>
    /// <p><b>R7g node types</b>: <code>cache.r7g.large</code>, <code>cache.r7g.xlarge</code>, <code>cache.r7g.2xlarge</code>, <code>cache.r7g.4xlarge</code>, <code>cache.r7g.8xlarge</code>, <code>cache.r7g.12xlarge</code>, <code>cache.r7g.16xlarge</code></p><note>
    /// <p>For region availability, see <a href="https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/CacheNodes.SupportedTypes.html#CacheNodes.SupportedTypesByRegion">Supported Node Types</a></p>
    /// </note>
    /// <p><b>R6g node types</b> (available only for Redis OSS engine version 5.0.6 onward and for Memcached engine version 1.5.16 onward): <code>cache.r6g.large</code>, <code>cache.r6g.xlarge</code>, <code>cache.r6g.2xlarge</code>, <code>cache.r6g.4xlarge</code>, <code>cache.r6g.8xlarge</code>, <code>cache.r6g.12xlarge</code>, <code>cache.r6g.16xlarge</code></p>
    /// <p><b>R5 node types:</b> <code>cache.r5.large</code>, <code>cache.r5.xlarge</code>, <code>cache.r5.2xlarge</code>, <code>cache.r5.4xlarge</code>, <code>cache.r5.12xlarge</code>, <code>cache.r5.24xlarge</code></p>
    /// <p><b>R4 node types:</b> <code>cache.r4.large</code>, <code>cache.r4.xlarge</code>, <code>cache.r4.2xlarge</code>, <code>cache.r4.4xlarge</code>, <code>cache.r4.8xlarge</code>, <code>cache.r4.16xlarge</code></p></li>
    /// <li>
    /// <p>Previous generation: (not recommended. Existing clusters are still supported but creation of new clusters is not supported for these types.)</p>
    /// <p><b>M2 node types:</b> <code>cache.m2.xlarge</code>, <code>cache.m2.2xlarge</code>, <code>cache.m2.4xlarge</code></p>
    /// <p><b>R3 node types:</b> <code>cache.r3.large</code>, <code>cache.r3.xlarge</code>, <code>cache.r3.2xlarge</code>, <code>cache.r3.4xlarge</code>, <code>cache.r3.8xlarge</code></p></li>
    /// </ul></li>
    /// </ul>
    /// <p><b>Additional node type info</b></p>
    /// <ul>
    /// <li>
    /// <p>All current generation instance types are created in Amazon VPC by default.</p></li>
    /// <li>
    /// <p>Valkey or Redis OSS append-only files (AOF) are not supported for T1 or T2 instances.</p></li>
    /// <li>
    /// <p>Valkey or Redis OSS Multi-AZ with automatic failover is not supported on T1 instances.</p></li>
    /// <li>
    /// <p>The configuration variables <code>appendonly</code> and <code>appendfsync</code> are not supported on Valkey, or on Redis OSS version 2.8.22 and later.</p></li>
    /// </ul>
    pub cache_node_type: ::std::option::Option<::std::string::String>,
    /// <p>The duration of the offering. in seconds.</p>
    pub duration: ::std::option::Option<i32>,
    /// <p>The fixed price charged for this offering.</p>
    pub fixed_price: ::std::option::Option<f64>,
    /// <p>The hourly price charged for this offering.</p>
    pub usage_price: ::std::option::Option<f64>,
    /// <p>The cache engine used by the offering.</p>
    pub product_description: ::std::option::Option<::std::string::String>,
    /// <p>The offering type.</p>
    pub offering_type: ::std::option::Option<::std::string::String>,
    /// <p>The recurring price charged to run this reserved cache node.</p>
    pub recurring_charges: ::std::option::Option<::std::vec::Vec<crate::types::RecurringCharge>>,
}
impl ReservedCacheNodesOffering {
    /// <p>A unique identifier for the reserved cache node offering.</p>
    pub fn reserved_cache_nodes_offering_id(&self) -> ::std::option::Option<&str> {
        self.reserved_cache_nodes_offering_id.as_deref()
    }
    /// <p>The cache node type for the reserved cache node.</p>
    /// <p>The following node types are supported by ElastiCache. Generally speaking, the current generation types provide more memory and computational power at lower cost when compared to their equivalent previous generation counterparts.</p>
    /// <ul>
    /// <li>
    /// <p>General purpose:</p>
    /// <ul>
    /// <li>
    /// <p>Current generation:</p>
    /// <p><b>M7g node types</b>: <code>cache.m7g.large</code>, <code>cache.m7g.xlarge</code>, <code>cache.m7g.2xlarge</code>, <code>cache.m7g.4xlarge</code>, <code>cache.m7g.8xlarge</code>, <code>cache.m7g.12xlarge</code>, <code>cache.m7g.16xlarge</code></p><note>
    /// <p>For region availability, see <a href="https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/CacheNodes.SupportedTypes.html#CacheNodes.SupportedTypesByRegion">Supported Node Types</a></p>
    /// </note>
    /// <p><b>M6g node types</b> (available only for Redis OSS engine version 5.0.6 onward and for Memcached engine version 1.5.16 onward): <code>cache.m6g.large</code>, <code>cache.m6g.xlarge</code>, <code>cache.m6g.2xlarge</code>, <code>cache.m6g.4xlarge</code>, <code>cache.m6g.8xlarge</code>, <code>cache.m6g.12xlarge</code>, <code>cache.m6g.16xlarge</code></p>
    /// <p><b>M5 node types:</b> <code>cache.m5.large</code>, <code>cache.m5.xlarge</code>, <code>cache.m5.2xlarge</code>, <code>cache.m5.4xlarge</code>, <code>cache.m5.12xlarge</code>, <code>cache.m5.24xlarge</code></p>
    /// <p><b>M4 node types:</b> <code>cache.m4.large</code>, <code>cache.m4.xlarge</code>, <code>cache.m4.2xlarge</code>, <code>cache.m4.4xlarge</code>, <code>cache.m4.10xlarge</code></p>
    /// <p><b>T4g node types</b> (available only for Redis OSS engine version 5.0.6 onward and Memcached engine version 1.5.16 onward): <code>cache.t4g.micro</code>, <code>cache.t4g.small</code>, <code>cache.t4g.medium</code></p>
    /// <p><b>T3 node types:</b> <code>cache.t3.micro</code>, <code>cache.t3.small</code>, <code>cache.t3.medium</code></p>
    /// <p><b>T2 node types:</b> <code>cache.t2.micro</code>, <code>cache.t2.small</code>, <code>cache.t2.medium</code></p></li>
    /// <li>
    /// <p>Previous generation: (not recommended. Existing clusters are still supported but creation of new clusters is not supported for these types.)</p>
    /// <p><b>T1 node types:</b> <code>cache.t1.micro</code></p>
    /// <p><b>M1 node types:</b> <code>cache.m1.small</code>, <code>cache.m1.medium</code>, <code>cache.m1.large</code>, <code>cache.m1.xlarge</code></p>
    /// <p><b>M3 node types:</b> <code>cache.m3.medium</code>, <code>cache.m3.large</code>, <code>cache.m3.xlarge</code>, <code>cache.m3.2xlarge</code></p></li>
    /// </ul></li>
    /// <li>
    /// <p>Compute optimized:</p>
    /// <ul>
    /// <li>
    /// <p>Previous generation: (not recommended. Existing clusters are still supported but creation of new clusters is not supported for these types.)</p>
    /// <p><b>C1 node types:</b> <code>cache.c1.xlarge</code></p></li>
    /// </ul></li>
    /// <li>
    /// <p>Memory optimized:</p>
    /// <ul>
    /// <li>
    /// <p>Current generation:</p>
    /// <p><b>R7g node types</b>: <code>cache.r7g.large</code>, <code>cache.r7g.xlarge</code>, <code>cache.r7g.2xlarge</code>, <code>cache.r7g.4xlarge</code>, <code>cache.r7g.8xlarge</code>, <code>cache.r7g.12xlarge</code>, <code>cache.r7g.16xlarge</code></p><note>
    /// <p>For region availability, see <a href="https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/CacheNodes.SupportedTypes.html#CacheNodes.SupportedTypesByRegion">Supported Node Types</a></p>
    /// </note>
    /// <p><b>R6g node types</b> (available only for Redis OSS engine version 5.0.6 onward and for Memcached engine version 1.5.16 onward): <code>cache.r6g.large</code>, <code>cache.r6g.xlarge</code>, <code>cache.r6g.2xlarge</code>, <code>cache.r6g.4xlarge</code>, <code>cache.r6g.8xlarge</code>, <code>cache.r6g.12xlarge</code>, <code>cache.r6g.16xlarge</code></p>
    /// <p><b>R5 node types:</b> <code>cache.r5.large</code>, <code>cache.r5.xlarge</code>, <code>cache.r5.2xlarge</code>, <code>cache.r5.4xlarge</code>, <code>cache.r5.12xlarge</code>, <code>cache.r5.24xlarge</code></p>
    /// <p><b>R4 node types:</b> <code>cache.r4.large</code>, <code>cache.r4.xlarge</code>, <code>cache.r4.2xlarge</code>, <code>cache.r4.4xlarge</code>, <code>cache.r4.8xlarge</code>, <code>cache.r4.16xlarge</code></p></li>
    /// <li>
    /// <p>Previous generation: (not recommended. Existing clusters are still supported but creation of new clusters is not supported for these types.)</p>
    /// <p><b>M2 node types:</b> <code>cache.m2.xlarge</code>, <code>cache.m2.2xlarge</code>, <code>cache.m2.4xlarge</code></p>
    /// <p><b>R3 node types:</b> <code>cache.r3.large</code>, <code>cache.r3.xlarge</code>, <code>cache.r3.2xlarge</code>, <code>cache.r3.4xlarge</code>, <code>cache.r3.8xlarge</code></p></li>
    /// </ul></li>
    /// </ul>
    /// <p><b>Additional node type info</b></p>
    /// <ul>
    /// <li>
    /// <p>All current generation instance types are created in Amazon VPC by default.</p></li>
    /// <li>
    /// <p>Valkey or Redis OSS append-only files (AOF) are not supported for T1 or T2 instances.</p></li>
    /// <li>
    /// <p>Valkey or Redis OSS Multi-AZ with automatic failover is not supported on T1 instances.</p></li>
    /// <li>
    /// <p>The configuration variables <code>appendonly</code> and <code>appendfsync</code> are not supported on Valkey, or on Redis OSS version 2.8.22 and later.</p></li>
    /// </ul>
    pub fn cache_node_type(&self) -> ::std::option::Option<&str> {
        self.cache_node_type.as_deref()
    }
    /// <p>The duration of the offering. in seconds.</p>
    pub fn duration(&self) -> ::std::option::Option<i32> {
        self.duration
    }
    /// <p>The fixed price charged for this offering.</p>
    pub fn fixed_price(&self) -> ::std::option::Option<f64> {
        self.fixed_price
    }
    /// <p>The hourly price charged for this offering.</p>
    pub fn usage_price(&self) -> ::std::option::Option<f64> {
        self.usage_price
    }
    /// <p>The cache engine used by the offering.</p>
    pub fn product_description(&self) -> ::std::option::Option<&str> {
        self.product_description.as_deref()
    }
    /// <p>The offering type.</p>
    pub fn offering_type(&self) -> ::std::option::Option<&str> {
        self.offering_type.as_deref()
    }
    /// <p>The recurring price charged to run this reserved cache node.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.recurring_charges.is_none()`.
    pub fn recurring_charges(&self) -> &[crate::types::RecurringCharge] {
        self.recurring_charges.as_deref().unwrap_or_default()
    }
}
impl ReservedCacheNodesOffering {
    /// Creates a new builder-style object to manufacture [`ReservedCacheNodesOffering`](crate::types::ReservedCacheNodesOffering).
    pub fn builder() -> crate::types::builders::ReservedCacheNodesOfferingBuilder {
        crate::types::builders::ReservedCacheNodesOfferingBuilder::default()
    }
}

/// A builder for [`ReservedCacheNodesOffering`](crate::types::ReservedCacheNodesOffering).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ReservedCacheNodesOfferingBuilder {
    pub(crate) reserved_cache_nodes_offering_id: ::std::option::Option<::std::string::String>,
    pub(crate) cache_node_type: ::std::option::Option<::std::string::String>,
    pub(crate) duration: ::std::option::Option<i32>,
    pub(crate) fixed_price: ::std::option::Option<f64>,
    pub(crate) usage_price: ::std::option::Option<f64>,
    pub(crate) product_description: ::std::option::Option<::std::string::String>,
    pub(crate) offering_type: ::std::option::Option<::std::string::String>,
    pub(crate) recurring_charges: ::std::option::Option<::std::vec::Vec<crate::types::RecurringCharge>>,
}
impl ReservedCacheNodesOfferingBuilder {
    /// <p>A unique identifier for the reserved cache node offering.</p>
    pub fn reserved_cache_nodes_offering_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.reserved_cache_nodes_offering_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the reserved cache node offering.</p>
    pub fn set_reserved_cache_nodes_offering_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.reserved_cache_nodes_offering_id = input;
        self
    }
    /// <p>A unique identifier for the reserved cache node offering.</p>
    pub fn get_reserved_cache_nodes_offering_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.reserved_cache_nodes_offering_id
    }
    /// <p>The cache node type for the reserved cache node.</p>
    /// <p>The following node types are supported by ElastiCache. Generally speaking, the current generation types provide more memory and computational power at lower cost when compared to their equivalent previous generation counterparts.</p>
    /// <ul>
    /// <li>
    /// <p>General purpose:</p>
    /// <ul>
    /// <li>
    /// <p>Current generation:</p>
    /// <p><b>M7g node types</b>: <code>cache.m7g.large</code>, <code>cache.m7g.xlarge</code>, <code>cache.m7g.2xlarge</code>, <code>cache.m7g.4xlarge</code>, <code>cache.m7g.8xlarge</code>, <code>cache.m7g.12xlarge</code>, <code>cache.m7g.16xlarge</code></p><note>
    /// <p>For region availability, see <a href="https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/CacheNodes.SupportedTypes.html#CacheNodes.SupportedTypesByRegion">Supported Node Types</a></p>
    /// </note>
    /// <p><b>M6g node types</b> (available only for Redis OSS engine version 5.0.6 onward and for Memcached engine version 1.5.16 onward): <code>cache.m6g.large</code>, <code>cache.m6g.xlarge</code>, <code>cache.m6g.2xlarge</code>, <code>cache.m6g.4xlarge</code>, <code>cache.m6g.8xlarge</code>, <code>cache.m6g.12xlarge</code>, <code>cache.m6g.16xlarge</code></p>
    /// <p><b>M5 node types:</b> <code>cache.m5.large</code>, <code>cache.m5.xlarge</code>, <code>cache.m5.2xlarge</code>, <code>cache.m5.4xlarge</code>, <code>cache.m5.12xlarge</code>, <code>cache.m5.24xlarge</code></p>
    /// <p><b>M4 node types:</b> <code>cache.m4.large</code>, <code>cache.m4.xlarge</code>, <code>cache.m4.2xlarge</code>, <code>cache.m4.4xlarge</code>, <code>cache.m4.10xlarge</code></p>
    /// <p><b>T4g node types</b> (available only for Redis OSS engine version 5.0.6 onward and Memcached engine version 1.5.16 onward): <code>cache.t4g.micro</code>, <code>cache.t4g.small</code>, <code>cache.t4g.medium</code></p>
    /// <p><b>T3 node types:</b> <code>cache.t3.micro</code>, <code>cache.t3.small</code>, <code>cache.t3.medium</code></p>
    /// <p><b>T2 node types:</b> <code>cache.t2.micro</code>, <code>cache.t2.small</code>, <code>cache.t2.medium</code></p></li>
    /// <li>
    /// <p>Previous generation: (not recommended. Existing clusters are still supported but creation of new clusters is not supported for these types.)</p>
    /// <p><b>T1 node types:</b> <code>cache.t1.micro</code></p>
    /// <p><b>M1 node types:</b> <code>cache.m1.small</code>, <code>cache.m1.medium</code>, <code>cache.m1.large</code>, <code>cache.m1.xlarge</code></p>
    /// <p><b>M3 node types:</b> <code>cache.m3.medium</code>, <code>cache.m3.large</code>, <code>cache.m3.xlarge</code>, <code>cache.m3.2xlarge</code></p></li>
    /// </ul></li>
    /// <li>
    /// <p>Compute optimized:</p>
    /// <ul>
    /// <li>
    /// <p>Previous generation: (not recommended. Existing clusters are still supported but creation of new clusters is not supported for these types.)</p>
    /// <p><b>C1 node types:</b> <code>cache.c1.xlarge</code></p></li>
    /// </ul></li>
    /// <li>
    /// <p>Memory optimized:</p>
    /// <ul>
    /// <li>
    /// <p>Current generation:</p>
    /// <p><b>R7g node types</b>: <code>cache.r7g.large</code>, <code>cache.r7g.xlarge</code>, <code>cache.r7g.2xlarge</code>, <code>cache.r7g.4xlarge</code>, <code>cache.r7g.8xlarge</code>, <code>cache.r7g.12xlarge</code>, <code>cache.r7g.16xlarge</code></p><note>
    /// <p>For region availability, see <a href="https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/CacheNodes.SupportedTypes.html#CacheNodes.SupportedTypesByRegion">Supported Node Types</a></p>
    /// </note>
    /// <p><b>R6g node types</b> (available only for Redis OSS engine version 5.0.6 onward and for Memcached engine version 1.5.16 onward): <code>cache.r6g.large</code>, <code>cache.r6g.xlarge</code>, <code>cache.r6g.2xlarge</code>, <code>cache.r6g.4xlarge</code>, <code>cache.r6g.8xlarge</code>, <code>cache.r6g.12xlarge</code>, <code>cache.r6g.16xlarge</code></p>
    /// <p><b>R5 node types:</b> <code>cache.r5.large</code>, <code>cache.r5.xlarge</code>, <code>cache.r5.2xlarge</code>, <code>cache.r5.4xlarge</code>, <code>cache.r5.12xlarge</code>, <code>cache.r5.24xlarge</code></p>
    /// <p><b>R4 node types:</b> <code>cache.r4.large</code>, <code>cache.r4.xlarge</code>, <code>cache.r4.2xlarge</code>, <code>cache.r4.4xlarge</code>, <code>cache.r4.8xlarge</code>, <code>cache.r4.16xlarge</code></p></li>
    /// <li>
    /// <p>Previous generation: (not recommended. Existing clusters are still supported but creation of new clusters is not supported for these types.)</p>
    /// <p><b>M2 node types:</b> <code>cache.m2.xlarge</code>, <code>cache.m2.2xlarge</code>, <code>cache.m2.4xlarge</code></p>
    /// <p><b>R3 node types:</b> <code>cache.r3.large</code>, <code>cache.r3.xlarge</code>, <code>cache.r3.2xlarge</code>, <code>cache.r3.4xlarge</code>, <code>cache.r3.8xlarge</code></p></li>
    /// </ul></li>
    /// </ul>
    /// <p><b>Additional node type info</b></p>
    /// <ul>
    /// <li>
    /// <p>All current generation instance types are created in Amazon VPC by default.</p></li>
    /// <li>
    /// <p>Valkey or Redis OSS append-only files (AOF) are not supported for T1 or T2 instances.</p></li>
    /// <li>
    /// <p>Valkey or Redis OSS Multi-AZ with automatic failover is not supported on T1 instances.</p></li>
    /// <li>
    /// <p>The configuration variables <code>appendonly</code> and <code>appendfsync</code> are not supported on Valkey, or on Redis OSS version 2.8.22 and later.</p></li>
    /// </ul>
    pub fn cache_node_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cache_node_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The cache node type for the reserved cache node.</p>
    /// <p>The following node types are supported by ElastiCache. Generally speaking, the current generation types provide more memory and computational power at lower cost when compared to their equivalent previous generation counterparts.</p>
    /// <ul>
    /// <li>
    /// <p>General purpose:</p>
    /// <ul>
    /// <li>
    /// <p>Current generation:</p>
    /// <p><b>M7g node types</b>: <code>cache.m7g.large</code>, <code>cache.m7g.xlarge</code>, <code>cache.m7g.2xlarge</code>, <code>cache.m7g.4xlarge</code>, <code>cache.m7g.8xlarge</code>, <code>cache.m7g.12xlarge</code>, <code>cache.m7g.16xlarge</code></p><note>
    /// <p>For region availability, see <a href="https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/CacheNodes.SupportedTypes.html#CacheNodes.SupportedTypesByRegion">Supported Node Types</a></p>
    /// </note>
    /// <p><b>M6g node types</b> (available only for Redis OSS engine version 5.0.6 onward and for Memcached engine version 1.5.16 onward): <code>cache.m6g.large</code>, <code>cache.m6g.xlarge</code>, <code>cache.m6g.2xlarge</code>, <code>cache.m6g.4xlarge</code>, <code>cache.m6g.8xlarge</code>, <code>cache.m6g.12xlarge</code>, <code>cache.m6g.16xlarge</code></p>
    /// <p><b>M5 node types:</b> <code>cache.m5.large</code>, <code>cache.m5.xlarge</code>, <code>cache.m5.2xlarge</code>, <code>cache.m5.4xlarge</code>, <code>cache.m5.12xlarge</code>, <code>cache.m5.24xlarge</code></p>
    /// <p><b>M4 node types:</b> <code>cache.m4.large</code>, <code>cache.m4.xlarge</code>, <code>cache.m4.2xlarge</code>, <code>cache.m4.4xlarge</code>, <code>cache.m4.10xlarge</code></p>
    /// <p><b>T4g node types</b> (available only for Redis OSS engine version 5.0.6 onward and Memcached engine version 1.5.16 onward): <code>cache.t4g.micro</code>, <code>cache.t4g.small</code>, <code>cache.t4g.medium</code></p>
    /// <p><b>T3 node types:</b> <code>cache.t3.micro</code>, <code>cache.t3.small</code>, <code>cache.t3.medium</code></p>
    /// <p><b>T2 node types:</b> <code>cache.t2.micro</code>, <code>cache.t2.small</code>, <code>cache.t2.medium</code></p></li>
    /// <li>
    /// <p>Previous generation: (not recommended. Existing clusters are still supported but creation of new clusters is not supported for these types.)</p>
    /// <p><b>T1 node types:</b> <code>cache.t1.micro</code></p>
    /// <p><b>M1 node types:</b> <code>cache.m1.small</code>, <code>cache.m1.medium</code>, <code>cache.m1.large</code>, <code>cache.m1.xlarge</code></p>
    /// <p><b>M3 node types:</b> <code>cache.m3.medium</code>, <code>cache.m3.large</code>, <code>cache.m3.xlarge</code>, <code>cache.m3.2xlarge</code></p></li>
    /// </ul></li>
    /// <li>
    /// <p>Compute optimized:</p>
    /// <ul>
    /// <li>
    /// <p>Previous generation: (not recommended. Existing clusters are still supported but creation of new clusters is not supported for these types.)</p>
    /// <p><b>C1 node types:</b> <code>cache.c1.xlarge</code></p></li>
    /// </ul></li>
    /// <li>
    /// <p>Memory optimized:</p>
    /// <ul>
    /// <li>
    /// <p>Current generation:</p>
    /// <p><b>R7g node types</b>: <code>cache.r7g.large</code>, <code>cache.r7g.xlarge</code>, <code>cache.r7g.2xlarge</code>, <code>cache.r7g.4xlarge</code>, <code>cache.r7g.8xlarge</code>, <code>cache.r7g.12xlarge</code>, <code>cache.r7g.16xlarge</code></p><note>
    /// <p>For region availability, see <a href="https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/CacheNodes.SupportedTypes.html#CacheNodes.SupportedTypesByRegion">Supported Node Types</a></p>
    /// </note>
    /// <p><b>R6g node types</b> (available only for Redis OSS engine version 5.0.6 onward and for Memcached engine version 1.5.16 onward): <code>cache.r6g.large</code>, <code>cache.r6g.xlarge</code>, <code>cache.r6g.2xlarge</code>, <code>cache.r6g.4xlarge</code>, <code>cache.r6g.8xlarge</code>, <code>cache.r6g.12xlarge</code>, <code>cache.r6g.16xlarge</code></p>
    /// <p><b>R5 node types:</b> <code>cache.r5.large</code>, <code>cache.r5.xlarge</code>, <code>cache.r5.2xlarge</code>, <code>cache.r5.4xlarge</code>, <code>cache.r5.12xlarge</code>, <code>cache.r5.24xlarge</code></p>
    /// <p><b>R4 node types:</b> <code>cache.r4.large</code>, <code>cache.r4.xlarge</code>, <code>cache.r4.2xlarge</code>, <code>cache.r4.4xlarge</code>, <code>cache.r4.8xlarge</code>, <code>cache.r4.16xlarge</code></p></li>
    /// <li>
    /// <p>Previous generation: (not recommended. Existing clusters are still supported but creation of new clusters is not supported for these types.)</p>
    /// <p><b>M2 node types:</b> <code>cache.m2.xlarge</code>, <code>cache.m2.2xlarge</code>, <code>cache.m2.4xlarge</code></p>
    /// <p><b>R3 node types:</b> <code>cache.r3.large</code>, <code>cache.r3.xlarge</code>, <code>cache.r3.2xlarge</code>, <code>cache.r3.4xlarge</code>, <code>cache.r3.8xlarge</code></p></li>
    /// </ul></li>
    /// </ul>
    /// <p><b>Additional node type info</b></p>
    /// <ul>
    /// <li>
    /// <p>All current generation instance types are created in Amazon VPC by default.</p></li>
    /// <li>
    /// <p>Valkey or Redis OSS append-only files (AOF) are not supported for T1 or T2 instances.</p></li>
    /// <li>
    /// <p>Valkey or Redis OSS Multi-AZ with automatic failover is not supported on T1 instances.</p></li>
    /// <li>
    /// <p>The configuration variables <code>appendonly</code> and <code>appendfsync</code> are not supported on Valkey, or on Redis OSS version 2.8.22 and later.</p></li>
    /// </ul>
    pub fn set_cache_node_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cache_node_type = input;
        self
    }
    /// <p>The cache node type for the reserved cache node.</p>
    /// <p>The following node types are supported by ElastiCache. Generally speaking, the current generation types provide more memory and computational power at lower cost when compared to their equivalent previous generation counterparts.</p>
    /// <ul>
    /// <li>
    /// <p>General purpose:</p>
    /// <ul>
    /// <li>
    /// <p>Current generation:</p>
    /// <p><b>M7g node types</b>: <code>cache.m7g.large</code>, <code>cache.m7g.xlarge</code>, <code>cache.m7g.2xlarge</code>, <code>cache.m7g.4xlarge</code>, <code>cache.m7g.8xlarge</code>, <code>cache.m7g.12xlarge</code>, <code>cache.m7g.16xlarge</code></p><note>
    /// <p>For region availability, see <a href="https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/CacheNodes.SupportedTypes.html#CacheNodes.SupportedTypesByRegion">Supported Node Types</a></p>
    /// </note>
    /// <p><b>M6g node types</b> (available only for Redis OSS engine version 5.0.6 onward and for Memcached engine version 1.5.16 onward): <code>cache.m6g.large</code>, <code>cache.m6g.xlarge</code>, <code>cache.m6g.2xlarge</code>, <code>cache.m6g.4xlarge</code>, <code>cache.m6g.8xlarge</code>, <code>cache.m6g.12xlarge</code>, <code>cache.m6g.16xlarge</code></p>
    /// <p><b>M5 node types:</b> <code>cache.m5.large</code>, <code>cache.m5.xlarge</code>, <code>cache.m5.2xlarge</code>, <code>cache.m5.4xlarge</code>, <code>cache.m5.12xlarge</code>, <code>cache.m5.24xlarge</code></p>
    /// <p><b>M4 node types:</b> <code>cache.m4.large</code>, <code>cache.m4.xlarge</code>, <code>cache.m4.2xlarge</code>, <code>cache.m4.4xlarge</code>, <code>cache.m4.10xlarge</code></p>
    /// <p><b>T4g node types</b> (available only for Redis OSS engine version 5.0.6 onward and Memcached engine version 1.5.16 onward): <code>cache.t4g.micro</code>, <code>cache.t4g.small</code>, <code>cache.t4g.medium</code></p>
    /// <p><b>T3 node types:</b> <code>cache.t3.micro</code>, <code>cache.t3.small</code>, <code>cache.t3.medium</code></p>
    /// <p><b>T2 node types:</b> <code>cache.t2.micro</code>, <code>cache.t2.small</code>, <code>cache.t2.medium</code></p></li>
    /// <li>
    /// <p>Previous generation: (not recommended. Existing clusters are still supported but creation of new clusters is not supported for these types.)</p>
    /// <p><b>T1 node types:</b> <code>cache.t1.micro</code></p>
    /// <p><b>M1 node types:</b> <code>cache.m1.small</code>, <code>cache.m1.medium</code>, <code>cache.m1.large</code>, <code>cache.m1.xlarge</code></p>
    /// <p><b>M3 node types:</b> <code>cache.m3.medium</code>, <code>cache.m3.large</code>, <code>cache.m3.xlarge</code>, <code>cache.m3.2xlarge</code></p></li>
    /// </ul></li>
    /// <li>
    /// <p>Compute optimized:</p>
    /// <ul>
    /// <li>
    /// <p>Previous generation: (not recommended. Existing clusters are still supported but creation of new clusters is not supported for these types.)</p>
    /// <p><b>C1 node types:</b> <code>cache.c1.xlarge</code></p></li>
    /// </ul></li>
    /// <li>
    /// <p>Memory optimized:</p>
    /// <ul>
    /// <li>
    /// <p>Current generation:</p>
    /// <p><b>R7g node types</b>: <code>cache.r7g.large</code>, <code>cache.r7g.xlarge</code>, <code>cache.r7g.2xlarge</code>, <code>cache.r7g.4xlarge</code>, <code>cache.r7g.8xlarge</code>, <code>cache.r7g.12xlarge</code>, <code>cache.r7g.16xlarge</code></p><note>
    /// <p>For region availability, see <a href="https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/CacheNodes.SupportedTypes.html#CacheNodes.SupportedTypesByRegion">Supported Node Types</a></p>
    /// </note>
    /// <p><b>R6g node types</b> (available only for Redis OSS engine version 5.0.6 onward and for Memcached engine version 1.5.16 onward): <code>cache.r6g.large</code>, <code>cache.r6g.xlarge</code>, <code>cache.r6g.2xlarge</code>, <code>cache.r6g.4xlarge</code>, <code>cache.r6g.8xlarge</code>, <code>cache.r6g.12xlarge</code>, <code>cache.r6g.16xlarge</code></p>
    /// <p><b>R5 node types:</b> <code>cache.r5.large</code>, <code>cache.r5.xlarge</code>, <code>cache.r5.2xlarge</code>, <code>cache.r5.4xlarge</code>, <code>cache.r5.12xlarge</code>, <code>cache.r5.24xlarge</code></p>
    /// <p><b>R4 node types:</b> <code>cache.r4.large</code>, <code>cache.r4.xlarge</code>, <code>cache.r4.2xlarge</code>, <code>cache.r4.4xlarge</code>, <code>cache.r4.8xlarge</code>, <code>cache.r4.16xlarge</code></p></li>
    /// <li>
    /// <p>Previous generation: (not recommended. Existing clusters are still supported but creation of new clusters is not supported for these types.)</p>
    /// <p><b>M2 node types:</b> <code>cache.m2.xlarge</code>, <code>cache.m2.2xlarge</code>, <code>cache.m2.4xlarge</code></p>
    /// <p><b>R3 node types:</b> <code>cache.r3.large</code>, <code>cache.r3.xlarge</code>, <code>cache.r3.2xlarge</code>, <code>cache.r3.4xlarge</code>, <code>cache.r3.8xlarge</code></p></li>
    /// </ul></li>
    /// </ul>
    /// <p><b>Additional node type info</b></p>
    /// <ul>
    /// <li>
    /// <p>All current generation instance types are created in Amazon VPC by default.</p></li>
    /// <li>
    /// <p>Valkey or Redis OSS append-only files (AOF) are not supported for T1 or T2 instances.</p></li>
    /// <li>
    /// <p>Valkey or Redis OSS Multi-AZ with automatic failover is not supported on T1 instances.</p></li>
    /// <li>
    /// <p>The configuration variables <code>appendonly</code> and <code>appendfsync</code> are not supported on Valkey, or on Redis OSS version 2.8.22 and later.</p></li>
    /// </ul>
    pub fn get_cache_node_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.cache_node_type
    }
    /// <p>The duration of the offering. in seconds.</p>
    pub fn duration(mut self, input: i32) -> Self {
        self.duration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The duration of the offering. in seconds.</p>
    pub fn set_duration(mut self, input: ::std::option::Option<i32>) -> Self {
        self.duration = input;
        self
    }
    /// <p>The duration of the offering. in seconds.</p>
    pub fn get_duration(&self) -> &::std::option::Option<i32> {
        &self.duration
    }
    /// <p>The fixed price charged for this offering.</p>
    pub fn fixed_price(mut self, input: f64) -> Self {
        self.fixed_price = ::std::option::Option::Some(input);
        self
    }
    /// <p>The fixed price charged for this offering.</p>
    pub fn set_fixed_price(mut self, input: ::std::option::Option<f64>) -> Self {
        self.fixed_price = input;
        self
    }
    /// <p>The fixed price charged for this offering.</p>
    pub fn get_fixed_price(&self) -> &::std::option::Option<f64> {
        &self.fixed_price
    }
    /// <p>The hourly price charged for this offering.</p>
    pub fn usage_price(mut self, input: f64) -> Self {
        self.usage_price = ::std::option::Option::Some(input);
        self
    }
    /// <p>The hourly price charged for this offering.</p>
    pub fn set_usage_price(mut self, input: ::std::option::Option<f64>) -> Self {
        self.usage_price = input;
        self
    }
    /// <p>The hourly price charged for this offering.</p>
    pub fn get_usage_price(&self) -> &::std::option::Option<f64> {
        &self.usage_price
    }
    /// <p>The cache engine used by the offering.</p>
    pub fn product_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.product_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The cache engine used by the offering.</p>
    pub fn set_product_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.product_description = input;
        self
    }
    /// <p>The cache engine used by the offering.</p>
    pub fn get_product_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.product_description
    }
    /// <p>The offering type.</p>
    pub fn offering_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.offering_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The offering type.</p>
    pub fn set_offering_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.offering_type = input;
        self
    }
    /// <p>The offering type.</p>
    pub fn get_offering_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.offering_type
    }
    /// Appends an item to `recurring_charges`.
    ///
    /// To override the contents of this collection use [`set_recurring_charges`](Self::set_recurring_charges).
    ///
    /// <p>The recurring price charged to run this reserved cache node.</p>
    pub fn recurring_charges(mut self, input: crate::types::RecurringCharge) -> Self {
        let mut v = self.recurring_charges.unwrap_or_default();
        v.push(input);
        self.recurring_charges = ::std::option::Option::Some(v);
        self
    }
    /// <p>The recurring price charged to run this reserved cache node.</p>
    pub fn set_recurring_charges(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::RecurringCharge>>) -> Self {
        self.recurring_charges = input;
        self
    }
    /// <p>The recurring price charged to run this reserved cache node.</p>
    pub fn get_recurring_charges(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RecurringCharge>> {
        &self.recurring_charges
    }
    /// Consumes the builder and constructs a [`ReservedCacheNodesOffering`](crate::types::ReservedCacheNodesOffering).
    pub fn build(self) -> crate::types::ReservedCacheNodesOffering {
        crate::types::ReservedCacheNodesOffering {
            reserved_cache_nodes_offering_id: self.reserved_cache_nodes_offering_id,
            cache_node_type: self.cache_node_type,
            duration: self.duration,
            fixed_price: self.fixed_price,
            usage_price: self.usage_price,
            product_description: self.product_description,
            offering_type: self.offering_type,
            recurring_charges: self.recurring_charges,
        }
    }
}
