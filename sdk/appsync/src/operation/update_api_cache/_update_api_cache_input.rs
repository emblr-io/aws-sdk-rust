// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the input of a <code>UpdateApiCache</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateApiCacheInput {
    /// <p>The GraphQL API ID.</p>
    pub api_id: ::std::option::Option<::std::string::String>,
    /// <p>TTL in seconds for cache entries.</p>
    /// <p>Valid values are 1–3,600 seconds.</p>
    pub ttl: ::std::option::Option<i64>,
    /// <p>Caching behavior.</p>
    /// <ul>
    /// <li>
    /// <p><b>FULL_REQUEST_CACHING</b>: All requests from the same user are cached. Individual resolvers are automatically cached. All API calls will try to return responses from the cache.</p></li>
    /// <li>
    /// <p><b>PER_RESOLVER_CACHING</b>: Individual resolvers that you specify are cached.</p></li>
    /// <li>
    /// <p><b>OPERATION_LEVEL_CACHING</b>: Full requests are cached together and returned without executing resolvers.</p></li>
    /// </ul>
    pub api_caching_behavior: ::std::option::Option<crate::types::ApiCachingBehavior>,
    /// <p>The cache instance type. Valid values are</p>
    /// <ul>
    /// <li>
    /// <p><code>SMALL</code></p></li>
    /// <li>
    /// <p><code>MEDIUM</code></p></li>
    /// <li>
    /// <p><code>LARGE</code></p></li>
    /// <li>
    /// <p><code>XLARGE</code></p></li>
    /// <li>
    /// <p><code>LARGE_2X</code></p></li>
    /// <li>
    /// <p><code>LARGE_4X</code></p></li>
    /// <li>
    /// <p><code>LARGE_8X</code> (not available in all regions)</p></li>
    /// <li>
    /// <p><code>LARGE_12X</code></p></li>
    /// </ul>
    /// <p>Historically, instance types were identified by an EC2-style value. As of July 2020, this is deprecated, and the generic identifiers above should be used.</p>
    /// <p>The following legacy instance types are available, but their use is discouraged:</p>
    /// <ul>
    /// <li>
    /// <p><b>T2_SMALL</b>: A t2.small instance type.</p></li>
    /// <li>
    /// <p><b>T2_MEDIUM</b>: A t2.medium instance type.</p></li>
    /// <li>
    /// <p><b>R4_LARGE</b>: A r4.large instance type.</p></li>
    /// <li>
    /// <p><b>R4_XLARGE</b>: A r4.xlarge instance type.</p></li>
    /// <li>
    /// <p><b>R4_2XLARGE</b>: A r4.2xlarge instance type.</p></li>
    /// <li>
    /// <p><b>R4_4XLARGE</b>: A r4.4xlarge instance type.</p></li>
    /// <li>
    /// <p><b>R4_8XLARGE</b>: A r4.8xlarge instance type.</p></li>
    /// </ul>
    pub r#type: ::std::option::Option<crate::types::ApiCacheType>,
    /// <p>Controls how cache health metrics will be emitted to CloudWatch. Cache health metrics include:</p>
    /// <ul>
    /// <li>
    /// <p>NetworkBandwidthOutAllowanceExceeded: The network packets dropped because the throughput exceeded the aggregated bandwidth limit. This is useful for diagnosing bottlenecks in a cache configuration.</p></li>
    /// <li>
    /// <p>EngineCPUUtilization: The CPU utilization (percentage) allocated to the Redis process. This is useful for diagnosing bottlenecks in a cache configuration.</p></li>
    /// </ul>
    /// <p>Metrics will be recorded by API ID. You can set the value to <code>ENABLED</code> or <code>DISABLED</code>.</p>
    pub health_metrics_config: ::std::option::Option<crate::types::CacheHealthMetricsConfig>,
}
impl UpdateApiCacheInput {
    /// <p>The GraphQL API ID.</p>
    pub fn api_id(&self) -> ::std::option::Option<&str> {
        self.api_id.as_deref()
    }
    /// <p>TTL in seconds for cache entries.</p>
    /// <p>Valid values are 1–3,600 seconds.</p>
    pub fn ttl(&self) -> ::std::option::Option<i64> {
        self.ttl
    }
    /// <p>Caching behavior.</p>
    /// <ul>
    /// <li>
    /// <p><b>FULL_REQUEST_CACHING</b>: All requests from the same user are cached. Individual resolvers are automatically cached. All API calls will try to return responses from the cache.</p></li>
    /// <li>
    /// <p><b>PER_RESOLVER_CACHING</b>: Individual resolvers that you specify are cached.</p></li>
    /// <li>
    /// <p><b>OPERATION_LEVEL_CACHING</b>: Full requests are cached together and returned without executing resolvers.</p></li>
    /// </ul>
    pub fn api_caching_behavior(&self) -> ::std::option::Option<&crate::types::ApiCachingBehavior> {
        self.api_caching_behavior.as_ref()
    }
    /// <p>The cache instance type. Valid values are</p>
    /// <ul>
    /// <li>
    /// <p><code>SMALL</code></p></li>
    /// <li>
    /// <p><code>MEDIUM</code></p></li>
    /// <li>
    /// <p><code>LARGE</code></p></li>
    /// <li>
    /// <p><code>XLARGE</code></p></li>
    /// <li>
    /// <p><code>LARGE_2X</code></p></li>
    /// <li>
    /// <p><code>LARGE_4X</code></p></li>
    /// <li>
    /// <p><code>LARGE_8X</code> (not available in all regions)</p></li>
    /// <li>
    /// <p><code>LARGE_12X</code></p></li>
    /// </ul>
    /// <p>Historically, instance types were identified by an EC2-style value. As of July 2020, this is deprecated, and the generic identifiers above should be used.</p>
    /// <p>The following legacy instance types are available, but their use is discouraged:</p>
    /// <ul>
    /// <li>
    /// <p><b>T2_SMALL</b>: A t2.small instance type.</p></li>
    /// <li>
    /// <p><b>T2_MEDIUM</b>: A t2.medium instance type.</p></li>
    /// <li>
    /// <p><b>R4_LARGE</b>: A r4.large instance type.</p></li>
    /// <li>
    /// <p><b>R4_XLARGE</b>: A r4.xlarge instance type.</p></li>
    /// <li>
    /// <p><b>R4_2XLARGE</b>: A r4.2xlarge instance type.</p></li>
    /// <li>
    /// <p><b>R4_4XLARGE</b>: A r4.4xlarge instance type.</p></li>
    /// <li>
    /// <p><b>R4_8XLARGE</b>: A r4.8xlarge instance type.</p></li>
    /// </ul>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::ApiCacheType> {
        self.r#type.as_ref()
    }
    /// <p>Controls how cache health metrics will be emitted to CloudWatch. Cache health metrics include:</p>
    /// <ul>
    /// <li>
    /// <p>NetworkBandwidthOutAllowanceExceeded: The network packets dropped because the throughput exceeded the aggregated bandwidth limit. This is useful for diagnosing bottlenecks in a cache configuration.</p></li>
    /// <li>
    /// <p>EngineCPUUtilization: The CPU utilization (percentage) allocated to the Redis process. This is useful for diagnosing bottlenecks in a cache configuration.</p></li>
    /// </ul>
    /// <p>Metrics will be recorded by API ID. You can set the value to <code>ENABLED</code> or <code>DISABLED</code>.</p>
    pub fn health_metrics_config(&self) -> ::std::option::Option<&crate::types::CacheHealthMetricsConfig> {
        self.health_metrics_config.as_ref()
    }
}
impl UpdateApiCacheInput {
    /// Creates a new builder-style object to manufacture [`UpdateApiCacheInput`](crate::operation::update_api_cache::UpdateApiCacheInput).
    pub fn builder() -> crate::operation::update_api_cache::builders::UpdateApiCacheInputBuilder {
        crate::operation::update_api_cache::builders::UpdateApiCacheInputBuilder::default()
    }
}

/// A builder for [`UpdateApiCacheInput`](crate::operation::update_api_cache::UpdateApiCacheInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateApiCacheInputBuilder {
    pub(crate) api_id: ::std::option::Option<::std::string::String>,
    pub(crate) ttl: ::std::option::Option<i64>,
    pub(crate) api_caching_behavior: ::std::option::Option<crate::types::ApiCachingBehavior>,
    pub(crate) r#type: ::std::option::Option<crate::types::ApiCacheType>,
    pub(crate) health_metrics_config: ::std::option::Option<crate::types::CacheHealthMetricsConfig>,
}
impl UpdateApiCacheInputBuilder {
    /// <p>The GraphQL API ID.</p>
    /// This field is required.
    pub fn api_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.api_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The GraphQL API ID.</p>
    pub fn set_api_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.api_id = input;
        self
    }
    /// <p>The GraphQL API ID.</p>
    pub fn get_api_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.api_id
    }
    /// <p>TTL in seconds for cache entries.</p>
    /// <p>Valid values are 1–3,600 seconds.</p>
    /// This field is required.
    pub fn ttl(mut self, input: i64) -> Self {
        self.ttl = ::std::option::Option::Some(input);
        self
    }
    /// <p>TTL in seconds for cache entries.</p>
    /// <p>Valid values are 1–3,600 seconds.</p>
    pub fn set_ttl(mut self, input: ::std::option::Option<i64>) -> Self {
        self.ttl = input;
        self
    }
    /// <p>TTL in seconds for cache entries.</p>
    /// <p>Valid values are 1–3,600 seconds.</p>
    pub fn get_ttl(&self) -> &::std::option::Option<i64> {
        &self.ttl
    }
    /// <p>Caching behavior.</p>
    /// <ul>
    /// <li>
    /// <p><b>FULL_REQUEST_CACHING</b>: All requests from the same user are cached. Individual resolvers are automatically cached. All API calls will try to return responses from the cache.</p></li>
    /// <li>
    /// <p><b>PER_RESOLVER_CACHING</b>: Individual resolvers that you specify are cached.</p></li>
    /// <li>
    /// <p><b>OPERATION_LEVEL_CACHING</b>: Full requests are cached together and returned without executing resolvers.</p></li>
    /// </ul>
    /// This field is required.
    pub fn api_caching_behavior(mut self, input: crate::types::ApiCachingBehavior) -> Self {
        self.api_caching_behavior = ::std::option::Option::Some(input);
        self
    }
    /// <p>Caching behavior.</p>
    /// <ul>
    /// <li>
    /// <p><b>FULL_REQUEST_CACHING</b>: All requests from the same user are cached. Individual resolvers are automatically cached. All API calls will try to return responses from the cache.</p></li>
    /// <li>
    /// <p><b>PER_RESOLVER_CACHING</b>: Individual resolvers that you specify are cached.</p></li>
    /// <li>
    /// <p><b>OPERATION_LEVEL_CACHING</b>: Full requests are cached together and returned without executing resolvers.</p></li>
    /// </ul>
    pub fn set_api_caching_behavior(mut self, input: ::std::option::Option<crate::types::ApiCachingBehavior>) -> Self {
        self.api_caching_behavior = input;
        self
    }
    /// <p>Caching behavior.</p>
    /// <ul>
    /// <li>
    /// <p><b>FULL_REQUEST_CACHING</b>: All requests from the same user are cached. Individual resolvers are automatically cached. All API calls will try to return responses from the cache.</p></li>
    /// <li>
    /// <p><b>PER_RESOLVER_CACHING</b>: Individual resolvers that you specify are cached.</p></li>
    /// <li>
    /// <p><b>OPERATION_LEVEL_CACHING</b>: Full requests are cached together and returned without executing resolvers.</p></li>
    /// </ul>
    pub fn get_api_caching_behavior(&self) -> &::std::option::Option<crate::types::ApiCachingBehavior> {
        &self.api_caching_behavior
    }
    /// <p>The cache instance type. Valid values are</p>
    /// <ul>
    /// <li>
    /// <p><code>SMALL</code></p></li>
    /// <li>
    /// <p><code>MEDIUM</code></p></li>
    /// <li>
    /// <p><code>LARGE</code></p></li>
    /// <li>
    /// <p><code>XLARGE</code></p></li>
    /// <li>
    /// <p><code>LARGE_2X</code></p></li>
    /// <li>
    /// <p><code>LARGE_4X</code></p></li>
    /// <li>
    /// <p><code>LARGE_8X</code> (not available in all regions)</p></li>
    /// <li>
    /// <p><code>LARGE_12X</code></p></li>
    /// </ul>
    /// <p>Historically, instance types were identified by an EC2-style value. As of July 2020, this is deprecated, and the generic identifiers above should be used.</p>
    /// <p>The following legacy instance types are available, but their use is discouraged:</p>
    /// <ul>
    /// <li>
    /// <p><b>T2_SMALL</b>: A t2.small instance type.</p></li>
    /// <li>
    /// <p><b>T2_MEDIUM</b>: A t2.medium instance type.</p></li>
    /// <li>
    /// <p><b>R4_LARGE</b>: A r4.large instance type.</p></li>
    /// <li>
    /// <p><b>R4_XLARGE</b>: A r4.xlarge instance type.</p></li>
    /// <li>
    /// <p><b>R4_2XLARGE</b>: A r4.2xlarge instance type.</p></li>
    /// <li>
    /// <p><b>R4_4XLARGE</b>: A r4.4xlarge instance type.</p></li>
    /// <li>
    /// <p><b>R4_8XLARGE</b>: A r4.8xlarge instance type.</p></li>
    /// </ul>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::ApiCacheType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The cache instance type. Valid values are</p>
    /// <ul>
    /// <li>
    /// <p><code>SMALL</code></p></li>
    /// <li>
    /// <p><code>MEDIUM</code></p></li>
    /// <li>
    /// <p><code>LARGE</code></p></li>
    /// <li>
    /// <p><code>XLARGE</code></p></li>
    /// <li>
    /// <p><code>LARGE_2X</code></p></li>
    /// <li>
    /// <p><code>LARGE_4X</code></p></li>
    /// <li>
    /// <p><code>LARGE_8X</code> (not available in all regions)</p></li>
    /// <li>
    /// <p><code>LARGE_12X</code></p></li>
    /// </ul>
    /// <p>Historically, instance types were identified by an EC2-style value. As of July 2020, this is deprecated, and the generic identifiers above should be used.</p>
    /// <p>The following legacy instance types are available, but their use is discouraged:</p>
    /// <ul>
    /// <li>
    /// <p><b>T2_SMALL</b>: A t2.small instance type.</p></li>
    /// <li>
    /// <p><b>T2_MEDIUM</b>: A t2.medium instance type.</p></li>
    /// <li>
    /// <p><b>R4_LARGE</b>: A r4.large instance type.</p></li>
    /// <li>
    /// <p><b>R4_XLARGE</b>: A r4.xlarge instance type.</p></li>
    /// <li>
    /// <p><b>R4_2XLARGE</b>: A r4.2xlarge instance type.</p></li>
    /// <li>
    /// <p><b>R4_4XLARGE</b>: A r4.4xlarge instance type.</p></li>
    /// <li>
    /// <p><b>R4_8XLARGE</b>: A r4.8xlarge instance type.</p></li>
    /// </ul>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::ApiCacheType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The cache instance type. Valid values are</p>
    /// <ul>
    /// <li>
    /// <p><code>SMALL</code></p></li>
    /// <li>
    /// <p><code>MEDIUM</code></p></li>
    /// <li>
    /// <p><code>LARGE</code></p></li>
    /// <li>
    /// <p><code>XLARGE</code></p></li>
    /// <li>
    /// <p><code>LARGE_2X</code></p></li>
    /// <li>
    /// <p><code>LARGE_4X</code></p></li>
    /// <li>
    /// <p><code>LARGE_8X</code> (not available in all regions)</p></li>
    /// <li>
    /// <p><code>LARGE_12X</code></p></li>
    /// </ul>
    /// <p>Historically, instance types were identified by an EC2-style value. As of July 2020, this is deprecated, and the generic identifiers above should be used.</p>
    /// <p>The following legacy instance types are available, but their use is discouraged:</p>
    /// <ul>
    /// <li>
    /// <p><b>T2_SMALL</b>: A t2.small instance type.</p></li>
    /// <li>
    /// <p><b>T2_MEDIUM</b>: A t2.medium instance type.</p></li>
    /// <li>
    /// <p><b>R4_LARGE</b>: A r4.large instance type.</p></li>
    /// <li>
    /// <p><b>R4_XLARGE</b>: A r4.xlarge instance type.</p></li>
    /// <li>
    /// <p><b>R4_2XLARGE</b>: A r4.2xlarge instance type.</p></li>
    /// <li>
    /// <p><b>R4_4XLARGE</b>: A r4.4xlarge instance type.</p></li>
    /// <li>
    /// <p><b>R4_8XLARGE</b>: A r4.8xlarge instance type.</p></li>
    /// </ul>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::ApiCacheType> {
        &self.r#type
    }
    /// <p>Controls how cache health metrics will be emitted to CloudWatch. Cache health metrics include:</p>
    /// <ul>
    /// <li>
    /// <p>NetworkBandwidthOutAllowanceExceeded: The network packets dropped because the throughput exceeded the aggregated bandwidth limit. This is useful for diagnosing bottlenecks in a cache configuration.</p></li>
    /// <li>
    /// <p>EngineCPUUtilization: The CPU utilization (percentage) allocated to the Redis process. This is useful for diagnosing bottlenecks in a cache configuration.</p></li>
    /// </ul>
    /// <p>Metrics will be recorded by API ID. You can set the value to <code>ENABLED</code> or <code>DISABLED</code>.</p>
    pub fn health_metrics_config(mut self, input: crate::types::CacheHealthMetricsConfig) -> Self {
        self.health_metrics_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Controls how cache health metrics will be emitted to CloudWatch. Cache health metrics include:</p>
    /// <ul>
    /// <li>
    /// <p>NetworkBandwidthOutAllowanceExceeded: The network packets dropped because the throughput exceeded the aggregated bandwidth limit. This is useful for diagnosing bottlenecks in a cache configuration.</p></li>
    /// <li>
    /// <p>EngineCPUUtilization: The CPU utilization (percentage) allocated to the Redis process. This is useful for diagnosing bottlenecks in a cache configuration.</p></li>
    /// </ul>
    /// <p>Metrics will be recorded by API ID. You can set the value to <code>ENABLED</code> or <code>DISABLED</code>.</p>
    pub fn set_health_metrics_config(mut self, input: ::std::option::Option<crate::types::CacheHealthMetricsConfig>) -> Self {
        self.health_metrics_config = input;
        self
    }
    /// <p>Controls how cache health metrics will be emitted to CloudWatch. Cache health metrics include:</p>
    /// <ul>
    /// <li>
    /// <p>NetworkBandwidthOutAllowanceExceeded: The network packets dropped because the throughput exceeded the aggregated bandwidth limit. This is useful for diagnosing bottlenecks in a cache configuration.</p></li>
    /// <li>
    /// <p>EngineCPUUtilization: The CPU utilization (percentage) allocated to the Redis process. This is useful for diagnosing bottlenecks in a cache configuration.</p></li>
    /// </ul>
    /// <p>Metrics will be recorded by API ID. You can set the value to <code>ENABLED</code> or <code>DISABLED</code>.</p>
    pub fn get_health_metrics_config(&self) -> &::std::option::Option<crate::types::CacheHealthMetricsConfig> {
        &self.health_metrics_config
    }
    /// Consumes the builder and constructs a [`UpdateApiCacheInput`](crate::operation::update_api_cache::UpdateApiCacheInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_api_cache::UpdateApiCacheInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_api_cache::UpdateApiCacheInput {
            api_id: self.api_id,
            ttl: self.ttl,
            api_caching_behavior: self.api_caching_behavior,
            r#type: self.r#type,
            health_metrics_config: self.health_metrics_config,
        })
    }
}
