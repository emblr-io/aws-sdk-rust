// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Steps of a leg that must be performed before the travel portion of the leg.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RouteFerryBeforeTravelStep {
    /// <p>Duration of the step.</p>
    /// <p><b>Unit</b>: <code>seconds</code></p>
    pub duration: i64,
    /// <p>Brief description of the step in the requested language.</p><note>
    /// <p>Only available when the TravelStepType is Default.</p>
    /// </note>
    pub instruction: ::std::option::Option<::std::string::String>,
    /// <p>Type of the step.</p>
    pub r#type: crate::types::RouteFerryBeforeTravelStepType,
}
impl RouteFerryBeforeTravelStep {
    /// <p>Duration of the step.</p>
    /// <p><b>Unit</b>: <code>seconds</code></p>
    pub fn duration(&self) -> i64 {
        self.duration
    }
    /// <p>Brief description of the step in the requested language.</p><note>
    /// <p>Only available when the TravelStepType is Default.</p>
    /// </note>
    pub fn instruction(&self) -> ::std::option::Option<&str> {
        self.instruction.as_deref()
    }
    /// <p>Type of the step.</p>
    pub fn r#type(&self) -> &crate::types::RouteFerryBeforeTravelStepType {
        &self.r#type
    }
}
impl RouteFerryBeforeTravelStep {
    /// Creates a new builder-style object to manufacture [`RouteFerryBeforeTravelStep`](crate::types::RouteFerryBeforeTravelStep).
    pub fn builder() -> crate::types::builders::RouteFerryBeforeTravelStepBuilder {
        crate::types::builders::RouteFerryBeforeTravelStepBuilder::default()
    }
}

/// A builder for [`RouteFerryBeforeTravelStep`](crate::types::RouteFerryBeforeTravelStep).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RouteFerryBeforeTravelStepBuilder {
    pub(crate) duration: ::std::option::Option<i64>,
    pub(crate) instruction: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::RouteFerryBeforeTravelStepType>,
}
impl RouteFerryBeforeTravelStepBuilder {
    /// <p>Duration of the step.</p>
    /// <p><b>Unit</b>: <code>seconds</code></p>
    /// This field is required.
    pub fn duration(mut self, input: i64) -> Self {
        self.duration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Duration of the step.</p>
    /// <p><b>Unit</b>: <code>seconds</code></p>
    pub fn set_duration(mut self, input: ::std::option::Option<i64>) -> Self {
        self.duration = input;
        self
    }
    /// <p>Duration of the step.</p>
    /// <p><b>Unit</b>: <code>seconds</code></p>
    pub fn get_duration(&self) -> &::std::option::Option<i64> {
        &self.duration
    }
    /// <p>Brief description of the step in the requested language.</p><note>
    /// <p>Only available when the TravelStepType is Default.</p>
    /// </note>
    pub fn instruction(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instruction = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Brief description of the step in the requested language.</p><note>
    /// <p>Only available when the TravelStepType is Default.</p>
    /// </note>
    pub fn set_instruction(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instruction = input;
        self
    }
    /// <p>Brief description of the step in the requested language.</p><note>
    /// <p>Only available when the TravelStepType is Default.</p>
    /// </note>
    pub fn get_instruction(&self) -> &::std::option::Option<::std::string::String> {
        &self.instruction
    }
    /// <p>Type of the step.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::RouteFerryBeforeTravelStepType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Type of the step.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::RouteFerryBeforeTravelStepType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>Type of the step.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::RouteFerryBeforeTravelStepType> {
        &self.r#type
    }
    /// Consumes the builder and constructs a [`RouteFerryBeforeTravelStep`](crate::types::RouteFerryBeforeTravelStep).
    /// This method will fail if any of the following fields are not set:
    /// - [`r#type`](crate::types::builders::RouteFerryBeforeTravelStepBuilder::type)
    pub fn build(self) -> ::std::result::Result<crate::types::RouteFerryBeforeTravelStep, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::RouteFerryBeforeTravelStep {
            duration: self.duration.unwrap_or_default(),
            instruction: self.instruction,
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building RouteFerryBeforeTravelStep",
                )
            })?,
        })
    }
}
