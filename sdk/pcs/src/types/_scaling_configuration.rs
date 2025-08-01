// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the boundaries of the compute node group auto scaling.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ScalingConfiguration {
    /// <p>The lower bound of the number of instances allowed in the compute fleet.</p>
    pub min_instance_count: i32,
    /// <p>The upper bound of the number of instances allowed in the compute fleet.</p>
    pub max_instance_count: i32,
}
impl ScalingConfiguration {
    /// <p>The lower bound of the number of instances allowed in the compute fleet.</p>
    pub fn min_instance_count(&self) -> i32 {
        self.min_instance_count
    }
    /// <p>The upper bound of the number of instances allowed in the compute fleet.</p>
    pub fn max_instance_count(&self) -> i32 {
        self.max_instance_count
    }
}
impl ScalingConfiguration {
    /// Creates a new builder-style object to manufacture [`ScalingConfiguration`](crate::types::ScalingConfiguration).
    pub fn builder() -> crate::types::builders::ScalingConfigurationBuilder {
        crate::types::builders::ScalingConfigurationBuilder::default()
    }
}

/// A builder for [`ScalingConfiguration`](crate::types::ScalingConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ScalingConfigurationBuilder {
    pub(crate) min_instance_count: ::std::option::Option<i32>,
    pub(crate) max_instance_count: ::std::option::Option<i32>,
}
impl ScalingConfigurationBuilder {
    /// <p>The lower bound of the number of instances allowed in the compute fleet.</p>
    /// This field is required.
    pub fn min_instance_count(mut self, input: i32) -> Self {
        self.min_instance_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The lower bound of the number of instances allowed in the compute fleet.</p>
    pub fn set_min_instance_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.min_instance_count = input;
        self
    }
    /// <p>The lower bound of the number of instances allowed in the compute fleet.</p>
    pub fn get_min_instance_count(&self) -> &::std::option::Option<i32> {
        &self.min_instance_count
    }
    /// <p>The upper bound of the number of instances allowed in the compute fleet.</p>
    /// This field is required.
    pub fn max_instance_count(mut self, input: i32) -> Self {
        self.max_instance_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The upper bound of the number of instances allowed in the compute fleet.</p>
    pub fn set_max_instance_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_instance_count = input;
        self
    }
    /// <p>The upper bound of the number of instances allowed in the compute fleet.</p>
    pub fn get_max_instance_count(&self) -> &::std::option::Option<i32> {
        &self.max_instance_count
    }
    /// Consumes the builder and constructs a [`ScalingConfiguration`](crate::types::ScalingConfiguration).
    pub fn build(self) -> crate::types::ScalingConfiguration {
        crate::types::ScalingConfiguration {
            min_instance_count: self.min_instance_count.unwrap_or_default(),
            max_instance_count: self.max_instance_count.unwrap_or_default(),
        }
    }
}
