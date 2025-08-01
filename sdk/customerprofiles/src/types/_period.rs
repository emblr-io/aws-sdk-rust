// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Defines a limit and the time period during which it is enforced.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Period {
    /// <p>The unit of time.</p>
    pub unit: crate::types::PeriodUnit,
    /// <p>The amount of time of the specified unit.</p>
    pub value: i32,
    /// <p>The maximum allowed number of destination invocations per profile.</p>
    pub max_invocations_per_profile: ::std::option::Option<i32>,
    /// <p>If set to true, there is no limit on the number of destination invocations per profile. The default is false.</p>
    pub unlimited: bool,
}
impl Period {
    /// <p>The unit of time.</p>
    pub fn unit(&self) -> &crate::types::PeriodUnit {
        &self.unit
    }
    /// <p>The amount of time of the specified unit.</p>
    pub fn value(&self) -> i32 {
        self.value
    }
    /// <p>The maximum allowed number of destination invocations per profile.</p>
    pub fn max_invocations_per_profile(&self) -> ::std::option::Option<i32> {
        self.max_invocations_per_profile
    }
    /// <p>If set to true, there is no limit on the number of destination invocations per profile. The default is false.</p>
    pub fn unlimited(&self) -> bool {
        self.unlimited
    }
}
impl Period {
    /// Creates a new builder-style object to manufacture [`Period`](crate::types::Period).
    pub fn builder() -> crate::types::builders::PeriodBuilder {
        crate::types::builders::PeriodBuilder::default()
    }
}

/// A builder for [`Period`](crate::types::Period).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PeriodBuilder {
    pub(crate) unit: ::std::option::Option<crate::types::PeriodUnit>,
    pub(crate) value: ::std::option::Option<i32>,
    pub(crate) max_invocations_per_profile: ::std::option::Option<i32>,
    pub(crate) unlimited: ::std::option::Option<bool>,
}
impl PeriodBuilder {
    /// <p>The unit of time.</p>
    /// This field is required.
    pub fn unit(mut self, input: crate::types::PeriodUnit) -> Self {
        self.unit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The unit of time.</p>
    pub fn set_unit(mut self, input: ::std::option::Option<crate::types::PeriodUnit>) -> Self {
        self.unit = input;
        self
    }
    /// <p>The unit of time.</p>
    pub fn get_unit(&self) -> &::std::option::Option<crate::types::PeriodUnit> {
        &self.unit
    }
    /// <p>The amount of time of the specified unit.</p>
    /// This field is required.
    pub fn value(mut self, input: i32) -> Self {
        self.value = ::std::option::Option::Some(input);
        self
    }
    /// <p>The amount of time of the specified unit.</p>
    pub fn set_value(mut self, input: ::std::option::Option<i32>) -> Self {
        self.value = input;
        self
    }
    /// <p>The amount of time of the specified unit.</p>
    pub fn get_value(&self) -> &::std::option::Option<i32> {
        &self.value
    }
    /// <p>The maximum allowed number of destination invocations per profile.</p>
    pub fn max_invocations_per_profile(mut self, input: i32) -> Self {
        self.max_invocations_per_profile = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum allowed number of destination invocations per profile.</p>
    pub fn set_max_invocations_per_profile(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_invocations_per_profile = input;
        self
    }
    /// <p>The maximum allowed number of destination invocations per profile.</p>
    pub fn get_max_invocations_per_profile(&self) -> &::std::option::Option<i32> {
        &self.max_invocations_per_profile
    }
    /// <p>If set to true, there is no limit on the number of destination invocations per profile. The default is false.</p>
    pub fn unlimited(mut self, input: bool) -> Self {
        self.unlimited = ::std::option::Option::Some(input);
        self
    }
    /// <p>If set to true, there is no limit on the number of destination invocations per profile. The default is false.</p>
    pub fn set_unlimited(mut self, input: ::std::option::Option<bool>) -> Self {
        self.unlimited = input;
        self
    }
    /// <p>If set to true, there is no limit on the number of destination invocations per profile. The default is false.</p>
    pub fn get_unlimited(&self) -> &::std::option::Option<bool> {
        &self.unlimited
    }
    /// Consumes the builder and constructs a [`Period`](crate::types::Period).
    /// This method will fail if any of the following fields are not set:
    /// - [`unit`](crate::types::builders::PeriodBuilder::unit)
    /// - [`value`](crate::types::builders::PeriodBuilder::value)
    pub fn build(self) -> ::std::result::Result<crate::types::Period, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Period {
            unit: self.unit.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "unit",
                    "unit was not specified but it is required when building Period",
                )
            })?,
            value: self.value.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "value",
                    "value was not specified but it is required when building Period",
                )
            })?,
            max_invocations_per_profile: self.max_invocations_per_profile,
            unlimited: self.unlimited.unwrap_or_default(),
        })
    }
}
