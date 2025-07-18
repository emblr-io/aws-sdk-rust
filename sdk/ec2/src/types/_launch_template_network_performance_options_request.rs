// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>When you configure network performance options in your launch template, your instance is geared for performance improvements based on the workload that it runs as soon as it's available.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LaunchTemplateNetworkPerformanceOptionsRequest {
    /// <p>Specify the bandwidth weighting option to boost the associated type of baseline bandwidth, as follows:</p>
    /// <dl>
    /// <dt>
    /// default
    /// </dt>
    /// <dd>
    /// <p>This option uses the standard bandwidth configuration for your instance type.</p>
    /// </dd>
    /// <dt>
    /// vpc-1
    /// </dt>
    /// <dd>
    /// <p>This option boosts your networking baseline bandwidth and reduces your EBS baseline bandwidth.</p>
    /// </dd>
    /// <dt>
    /// ebs-1
    /// </dt>
    /// <dd>
    /// <p>This option boosts your EBS baseline bandwidth and reduces your networking baseline bandwidth.</p>
    /// </dd>
    /// </dl>
    pub bandwidth_weighting: ::std::option::Option<crate::types::InstanceBandwidthWeighting>,
}
impl LaunchTemplateNetworkPerformanceOptionsRequest {
    /// <p>Specify the bandwidth weighting option to boost the associated type of baseline bandwidth, as follows:</p>
    /// <dl>
    /// <dt>
    /// default
    /// </dt>
    /// <dd>
    /// <p>This option uses the standard bandwidth configuration for your instance type.</p>
    /// </dd>
    /// <dt>
    /// vpc-1
    /// </dt>
    /// <dd>
    /// <p>This option boosts your networking baseline bandwidth and reduces your EBS baseline bandwidth.</p>
    /// </dd>
    /// <dt>
    /// ebs-1
    /// </dt>
    /// <dd>
    /// <p>This option boosts your EBS baseline bandwidth and reduces your networking baseline bandwidth.</p>
    /// </dd>
    /// </dl>
    pub fn bandwidth_weighting(&self) -> ::std::option::Option<&crate::types::InstanceBandwidthWeighting> {
        self.bandwidth_weighting.as_ref()
    }
}
impl LaunchTemplateNetworkPerformanceOptionsRequest {
    /// Creates a new builder-style object to manufacture [`LaunchTemplateNetworkPerformanceOptionsRequest`](crate::types::LaunchTemplateNetworkPerformanceOptionsRequest).
    pub fn builder() -> crate::types::builders::LaunchTemplateNetworkPerformanceOptionsRequestBuilder {
        crate::types::builders::LaunchTemplateNetworkPerformanceOptionsRequestBuilder::default()
    }
}

/// A builder for [`LaunchTemplateNetworkPerformanceOptionsRequest`](crate::types::LaunchTemplateNetworkPerformanceOptionsRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LaunchTemplateNetworkPerformanceOptionsRequestBuilder {
    pub(crate) bandwidth_weighting: ::std::option::Option<crate::types::InstanceBandwidthWeighting>,
}
impl LaunchTemplateNetworkPerformanceOptionsRequestBuilder {
    /// <p>Specify the bandwidth weighting option to boost the associated type of baseline bandwidth, as follows:</p>
    /// <dl>
    /// <dt>
    /// default
    /// </dt>
    /// <dd>
    /// <p>This option uses the standard bandwidth configuration for your instance type.</p>
    /// </dd>
    /// <dt>
    /// vpc-1
    /// </dt>
    /// <dd>
    /// <p>This option boosts your networking baseline bandwidth and reduces your EBS baseline bandwidth.</p>
    /// </dd>
    /// <dt>
    /// ebs-1
    /// </dt>
    /// <dd>
    /// <p>This option boosts your EBS baseline bandwidth and reduces your networking baseline bandwidth.</p>
    /// </dd>
    /// </dl>
    pub fn bandwidth_weighting(mut self, input: crate::types::InstanceBandwidthWeighting) -> Self {
        self.bandwidth_weighting = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specify the bandwidth weighting option to boost the associated type of baseline bandwidth, as follows:</p>
    /// <dl>
    /// <dt>
    /// default
    /// </dt>
    /// <dd>
    /// <p>This option uses the standard bandwidth configuration for your instance type.</p>
    /// </dd>
    /// <dt>
    /// vpc-1
    /// </dt>
    /// <dd>
    /// <p>This option boosts your networking baseline bandwidth and reduces your EBS baseline bandwidth.</p>
    /// </dd>
    /// <dt>
    /// ebs-1
    /// </dt>
    /// <dd>
    /// <p>This option boosts your EBS baseline bandwidth and reduces your networking baseline bandwidth.</p>
    /// </dd>
    /// </dl>
    pub fn set_bandwidth_weighting(mut self, input: ::std::option::Option<crate::types::InstanceBandwidthWeighting>) -> Self {
        self.bandwidth_weighting = input;
        self
    }
    /// <p>Specify the bandwidth weighting option to boost the associated type of baseline bandwidth, as follows:</p>
    /// <dl>
    /// <dt>
    /// default
    /// </dt>
    /// <dd>
    /// <p>This option uses the standard bandwidth configuration for your instance type.</p>
    /// </dd>
    /// <dt>
    /// vpc-1
    /// </dt>
    /// <dd>
    /// <p>This option boosts your networking baseline bandwidth and reduces your EBS baseline bandwidth.</p>
    /// </dd>
    /// <dt>
    /// ebs-1
    /// </dt>
    /// <dd>
    /// <p>This option boosts your EBS baseline bandwidth and reduces your networking baseline bandwidth.</p>
    /// </dd>
    /// </dl>
    pub fn get_bandwidth_weighting(&self) -> &::std::option::Option<crate::types::InstanceBandwidthWeighting> {
        &self.bandwidth_weighting
    }
    /// Consumes the builder and constructs a [`LaunchTemplateNetworkPerformanceOptionsRequest`](crate::types::LaunchTemplateNetworkPerformanceOptionsRequest).
    pub fn build(self) -> crate::types::LaunchTemplateNetworkPerformanceOptionsRequest {
        crate::types::LaunchTemplateNetworkPerformanceOptionsRequest {
            bandwidth_weighting: self.bandwidth_weighting,
        }
    }
}
