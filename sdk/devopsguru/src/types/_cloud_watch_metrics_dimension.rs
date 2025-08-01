// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The dimension of an Amazon CloudWatch metric that is used when DevOps Guru analyzes the resources in your account for operational problems and anomalous behavior. A dimension is a name/value pair that is part of the identity of a metric. A metric can have up to 10 dimensions. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html#Dimension">Dimensions</a> in the <i>Amazon CloudWatch User Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CloudWatchMetricsDimension {
    /// <p>The name of the CloudWatch dimension.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The value of the CloudWatch dimension.</p>
    pub value: ::std::option::Option<::std::string::String>,
}
impl CloudWatchMetricsDimension {
    /// <p>The name of the CloudWatch dimension.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The value of the CloudWatch dimension.</p>
    pub fn value(&self) -> ::std::option::Option<&str> {
        self.value.as_deref()
    }
}
impl CloudWatchMetricsDimension {
    /// Creates a new builder-style object to manufacture [`CloudWatchMetricsDimension`](crate::types::CloudWatchMetricsDimension).
    pub fn builder() -> crate::types::builders::CloudWatchMetricsDimensionBuilder {
        crate::types::builders::CloudWatchMetricsDimensionBuilder::default()
    }
}

/// A builder for [`CloudWatchMetricsDimension`](crate::types::CloudWatchMetricsDimension).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CloudWatchMetricsDimensionBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) value: ::std::option::Option<::std::string::String>,
}
impl CloudWatchMetricsDimensionBuilder {
    /// <p>The name of the CloudWatch dimension.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the CloudWatch dimension.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the CloudWatch dimension.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The value of the CloudWatch dimension.</p>
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value of the CloudWatch dimension.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p>The value of the CloudWatch dimension.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// Consumes the builder and constructs a [`CloudWatchMetricsDimension`](crate::types::CloudWatchMetricsDimension).
    pub fn build(self) -> crate::types::CloudWatchMetricsDimension {
        crate::types::CloudWatchMetricsDimension {
            name: self.name,
            value: self.value,
        }
    }
}
