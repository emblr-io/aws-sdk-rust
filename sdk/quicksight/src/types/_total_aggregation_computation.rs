// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The total aggregation computation configuration.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TotalAggregationComputation {
    /// <p>The ID for a computation.</p>
    pub computation_id: ::std::string::String,
    /// <p>The name of a computation.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The value field that is used in a computation.</p>
    pub value: ::std::option::Option<crate::types::MeasureField>,
}
impl TotalAggregationComputation {
    /// <p>The ID for a computation.</p>
    pub fn computation_id(&self) -> &str {
        use std::ops::Deref;
        self.computation_id.deref()
    }
    /// <p>The name of a computation.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The value field that is used in a computation.</p>
    pub fn value(&self) -> ::std::option::Option<&crate::types::MeasureField> {
        self.value.as_ref()
    }
}
impl TotalAggregationComputation {
    /// Creates a new builder-style object to manufacture [`TotalAggregationComputation`](crate::types::TotalAggregationComputation).
    pub fn builder() -> crate::types::builders::TotalAggregationComputationBuilder {
        crate::types::builders::TotalAggregationComputationBuilder::default()
    }
}

/// A builder for [`TotalAggregationComputation`](crate::types::TotalAggregationComputation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TotalAggregationComputationBuilder {
    pub(crate) computation_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) value: ::std::option::Option<crate::types::MeasureField>,
}
impl TotalAggregationComputationBuilder {
    /// <p>The ID for a computation.</p>
    /// This field is required.
    pub fn computation_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.computation_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID for a computation.</p>
    pub fn set_computation_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.computation_id = input;
        self
    }
    /// <p>The ID for a computation.</p>
    pub fn get_computation_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.computation_id
    }
    /// <p>The name of a computation.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of a computation.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of a computation.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The value field that is used in a computation.</p>
    pub fn value(mut self, input: crate::types::MeasureField) -> Self {
        self.value = ::std::option::Option::Some(input);
        self
    }
    /// <p>The value field that is used in a computation.</p>
    pub fn set_value(mut self, input: ::std::option::Option<crate::types::MeasureField>) -> Self {
        self.value = input;
        self
    }
    /// <p>The value field that is used in a computation.</p>
    pub fn get_value(&self) -> &::std::option::Option<crate::types::MeasureField> {
        &self.value
    }
    /// Consumes the builder and constructs a [`TotalAggregationComputation`](crate::types::TotalAggregationComputation).
    /// This method will fail if any of the following fields are not set:
    /// - [`computation_id`](crate::types::builders::TotalAggregationComputationBuilder::computation_id)
    pub fn build(self) -> ::std::result::Result<crate::types::TotalAggregationComputation, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::TotalAggregationComputation {
            computation_id: self.computation_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "computation_id",
                    "computation_id was not specified but it is required when building TotalAggregationComputation",
                )
            })?,
            name: self.name,
            value: self.value,
        })
    }
}
