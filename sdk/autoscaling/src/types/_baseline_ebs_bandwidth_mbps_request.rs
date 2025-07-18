// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the minimum and maximum for the <code>BaselineEbsBandwidthMbps</code> object when you specify <a href="https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_InstanceRequirements.html">InstanceRequirements</a> for an Auto Scaling group.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BaselineEbsBandwidthMbpsRequest {
    /// <p>The minimum value in Mbps.</p>
    pub min: ::std::option::Option<i32>,
    /// <p>The maximum value in Mbps.</p>
    pub max: ::std::option::Option<i32>,
}
impl BaselineEbsBandwidthMbpsRequest {
    /// <p>The minimum value in Mbps.</p>
    pub fn min(&self) -> ::std::option::Option<i32> {
        self.min
    }
    /// <p>The maximum value in Mbps.</p>
    pub fn max(&self) -> ::std::option::Option<i32> {
        self.max
    }
}
impl BaselineEbsBandwidthMbpsRequest {
    /// Creates a new builder-style object to manufacture [`BaselineEbsBandwidthMbpsRequest`](crate::types::BaselineEbsBandwidthMbpsRequest).
    pub fn builder() -> crate::types::builders::BaselineEbsBandwidthMbpsRequestBuilder {
        crate::types::builders::BaselineEbsBandwidthMbpsRequestBuilder::default()
    }
}

/// A builder for [`BaselineEbsBandwidthMbpsRequest`](crate::types::BaselineEbsBandwidthMbpsRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BaselineEbsBandwidthMbpsRequestBuilder {
    pub(crate) min: ::std::option::Option<i32>,
    pub(crate) max: ::std::option::Option<i32>,
}
impl BaselineEbsBandwidthMbpsRequestBuilder {
    /// <p>The minimum value in Mbps.</p>
    pub fn min(mut self, input: i32) -> Self {
        self.min = ::std::option::Option::Some(input);
        self
    }
    /// <p>The minimum value in Mbps.</p>
    pub fn set_min(mut self, input: ::std::option::Option<i32>) -> Self {
        self.min = input;
        self
    }
    /// <p>The minimum value in Mbps.</p>
    pub fn get_min(&self) -> &::std::option::Option<i32> {
        &self.min
    }
    /// <p>The maximum value in Mbps.</p>
    pub fn max(mut self, input: i32) -> Self {
        self.max = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum value in Mbps.</p>
    pub fn set_max(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max = input;
        self
    }
    /// <p>The maximum value in Mbps.</p>
    pub fn get_max(&self) -> &::std::option::Option<i32> {
        &self.max
    }
    /// Consumes the builder and constructs a [`BaselineEbsBandwidthMbpsRequest`](crate::types::BaselineEbsBandwidthMbpsRequest).
    pub fn build(self) -> crate::types::BaselineEbsBandwidthMbpsRequest {
        crate::types::BaselineEbsBandwidthMbpsRequest {
            min: self.min,
            max: self.max,
        }
    }
}
