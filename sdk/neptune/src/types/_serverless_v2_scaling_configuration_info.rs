// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Shows the scaling configuration for a Neptune Serverless DB cluster.</p>
/// <p>For more information, see <a href="https://docs.aws.amazon.com/neptune/latest/userguide/neptune-serverless-using.html">Using Amazon Neptune Serverless</a> in the <i>Amazon Neptune User Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ServerlessV2ScalingConfigurationInfo {
    /// <p>The minimum number of Neptune capacity units (NCUs) for a DB instance in a Neptune Serverless cluster. You can specify NCU values in half-step increments, such as 8, 8.5, 9, and so on.</p>
    pub min_capacity: ::std::option::Option<f64>,
    /// <p>The maximum number of Neptune capacity units (NCUs) for a DB instance in a Neptune Serverless cluster. You can specify NCU values in half-step increments, such as 40, 40.5, 41, and so on.</p>
    pub max_capacity: ::std::option::Option<f64>,
}
impl ServerlessV2ScalingConfigurationInfo {
    /// <p>The minimum number of Neptune capacity units (NCUs) for a DB instance in a Neptune Serverless cluster. You can specify NCU values in half-step increments, such as 8, 8.5, 9, and so on.</p>
    pub fn min_capacity(&self) -> ::std::option::Option<f64> {
        self.min_capacity
    }
    /// <p>The maximum number of Neptune capacity units (NCUs) for a DB instance in a Neptune Serverless cluster. You can specify NCU values in half-step increments, such as 40, 40.5, 41, and so on.</p>
    pub fn max_capacity(&self) -> ::std::option::Option<f64> {
        self.max_capacity
    }
}
impl ServerlessV2ScalingConfigurationInfo {
    /// Creates a new builder-style object to manufacture [`ServerlessV2ScalingConfigurationInfo`](crate::types::ServerlessV2ScalingConfigurationInfo).
    pub fn builder() -> crate::types::builders::ServerlessV2ScalingConfigurationInfoBuilder {
        crate::types::builders::ServerlessV2ScalingConfigurationInfoBuilder::default()
    }
}

/// A builder for [`ServerlessV2ScalingConfigurationInfo`](crate::types::ServerlessV2ScalingConfigurationInfo).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ServerlessV2ScalingConfigurationInfoBuilder {
    pub(crate) min_capacity: ::std::option::Option<f64>,
    pub(crate) max_capacity: ::std::option::Option<f64>,
}
impl ServerlessV2ScalingConfigurationInfoBuilder {
    /// <p>The minimum number of Neptune capacity units (NCUs) for a DB instance in a Neptune Serverless cluster. You can specify NCU values in half-step increments, such as 8, 8.5, 9, and so on.</p>
    pub fn min_capacity(mut self, input: f64) -> Self {
        self.min_capacity = ::std::option::Option::Some(input);
        self
    }
    /// <p>The minimum number of Neptune capacity units (NCUs) for a DB instance in a Neptune Serverless cluster. You can specify NCU values in half-step increments, such as 8, 8.5, 9, and so on.</p>
    pub fn set_min_capacity(mut self, input: ::std::option::Option<f64>) -> Self {
        self.min_capacity = input;
        self
    }
    /// <p>The minimum number of Neptune capacity units (NCUs) for a DB instance in a Neptune Serverless cluster. You can specify NCU values in half-step increments, such as 8, 8.5, 9, and so on.</p>
    pub fn get_min_capacity(&self) -> &::std::option::Option<f64> {
        &self.min_capacity
    }
    /// <p>The maximum number of Neptune capacity units (NCUs) for a DB instance in a Neptune Serverless cluster. You can specify NCU values in half-step increments, such as 40, 40.5, 41, and so on.</p>
    pub fn max_capacity(mut self, input: f64) -> Self {
        self.max_capacity = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of Neptune capacity units (NCUs) for a DB instance in a Neptune Serverless cluster. You can specify NCU values in half-step increments, such as 40, 40.5, 41, and so on.</p>
    pub fn set_max_capacity(mut self, input: ::std::option::Option<f64>) -> Self {
        self.max_capacity = input;
        self
    }
    /// <p>The maximum number of Neptune capacity units (NCUs) for a DB instance in a Neptune Serverless cluster. You can specify NCU values in half-step increments, such as 40, 40.5, 41, and so on.</p>
    pub fn get_max_capacity(&self) -> &::std::option::Option<f64> {
        &self.max_capacity
    }
    /// Consumes the builder and constructs a [`ServerlessV2ScalingConfigurationInfo`](crate::types::ServerlessV2ScalingConfigurationInfo).
    pub fn build(self) -> crate::types::ServerlessV2ScalingConfigurationInfo {
        crate::types::ServerlessV2ScalingConfigurationInfo {
            min_capacity: self.min_capacity,
            max_capacity: self.max_capacity,
        }
    }
}
