// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The optional auto scaling capacity settings for a table in provisioned capacity mode.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AutoScalingSpecification {
    /// <p>The auto scaling settings for the table's write capacity.</p>
    pub write_capacity_auto_scaling: ::std::option::Option<crate::types::AutoScalingSettings>,
    /// <p>The auto scaling settings for the table's read capacity.</p>
    pub read_capacity_auto_scaling: ::std::option::Option<crate::types::AutoScalingSettings>,
}
impl AutoScalingSpecification {
    /// <p>The auto scaling settings for the table's write capacity.</p>
    pub fn write_capacity_auto_scaling(&self) -> ::std::option::Option<&crate::types::AutoScalingSettings> {
        self.write_capacity_auto_scaling.as_ref()
    }
    /// <p>The auto scaling settings for the table's read capacity.</p>
    pub fn read_capacity_auto_scaling(&self) -> ::std::option::Option<&crate::types::AutoScalingSettings> {
        self.read_capacity_auto_scaling.as_ref()
    }
}
impl AutoScalingSpecification {
    /// Creates a new builder-style object to manufacture [`AutoScalingSpecification`](crate::types::AutoScalingSpecification).
    pub fn builder() -> crate::types::builders::AutoScalingSpecificationBuilder {
        crate::types::builders::AutoScalingSpecificationBuilder::default()
    }
}

/// A builder for [`AutoScalingSpecification`](crate::types::AutoScalingSpecification).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AutoScalingSpecificationBuilder {
    pub(crate) write_capacity_auto_scaling: ::std::option::Option<crate::types::AutoScalingSettings>,
    pub(crate) read_capacity_auto_scaling: ::std::option::Option<crate::types::AutoScalingSettings>,
}
impl AutoScalingSpecificationBuilder {
    /// <p>The auto scaling settings for the table's write capacity.</p>
    pub fn write_capacity_auto_scaling(mut self, input: crate::types::AutoScalingSettings) -> Self {
        self.write_capacity_auto_scaling = ::std::option::Option::Some(input);
        self
    }
    /// <p>The auto scaling settings for the table's write capacity.</p>
    pub fn set_write_capacity_auto_scaling(mut self, input: ::std::option::Option<crate::types::AutoScalingSettings>) -> Self {
        self.write_capacity_auto_scaling = input;
        self
    }
    /// <p>The auto scaling settings for the table's write capacity.</p>
    pub fn get_write_capacity_auto_scaling(&self) -> &::std::option::Option<crate::types::AutoScalingSettings> {
        &self.write_capacity_auto_scaling
    }
    /// <p>The auto scaling settings for the table's read capacity.</p>
    pub fn read_capacity_auto_scaling(mut self, input: crate::types::AutoScalingSettings) -> Self {
        self.read_capacity_auto_scaling = ::std::option::Option::Some(input);
        self
    }
    /// <p>The auto scaling settings for the table's read capacity.</p>
    pub fn set_read_capacity_auto_scaling(mut self, input: ::std::option::Option<crate::types::AutoScalingSettings>) -> Self {
        self.read_capacity_auto_scaling = input;
        self
    }
    /// <p>The auto scaling settings for the table's read capacity.</p>
    pub fn get_read_capacity_auto_scaling(&self) -> &::std::option::Option<crate::types::AutoScalingSettings> {
        &self.read_capacity_auto_scaling
    }
    /// Consumes the builder and constructs a [`AutoScalingSpecification`](crate::types::AutoScalingSpecification).
    pub fn build(self) -> crate::types::AutoScalingSpecification {
        crate::types::AutoScalingSpecification {
            write_capacity_auto_scaling: self.write_capacity_auto_scaling,
            read_capacity_auto_scaling: self.read_capacity_auto_scaling,
        }
    }
}
