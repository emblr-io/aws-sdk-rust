// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Configuration information required to enable chat orchestration for your Amazon Q Business application.</p><note>
/// <p>Chat orchestration is optimized to work for English language content. For more details on language support in Amazon Q Business, see <a href="https://docs.aws.amazon.com/amazonq/latest/qbusiness-ug/supported-languages.html">Supported languages</a>.</p>
/// </note>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OrchestrationConfiguration {
    /// <p>Status information about whether chat orchestration is activated or deactivated for your Amazon Q Business application.</p>
    pub control: crate::types::OrchestrationControl,
}
impl OrchestrationConfiguration {
    /// <p>Status information about whether chat orchestration is activated or deactivated for your Amazon Q Business application.</p>
    pub fn control(&self) -> &crate::types::OrchestrationControl {
        &self.control
    }
}
impl OrchestrationConfiguration {
    /// Creates a new builder-style object to manufacture [`OrchestrationConfiguration`](crate::types::OrchestrationConfiguration).
    pub fn builder() -> crate::types::builders::OrchestrationConfigurationBuilder {
        crate::types::builders::OrchestrationConfigurationBuilder::default()
    }
}

/// A builder for [`OrchestrationConfiguration`](crate::types::OrchestrationConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OrchestrationConfigurationBuilder {
    pub(crate) control: ::std::option::Option<crate::types::OrchestrationControl>,
}
impl OrchestrationConfigurationBuilder {
    /// <p>Status information about whether chat orchestration is activated or deactivated for your Amazon Q Business application.</p>
    /// This field is required.
    pub fn control(mut self, input: crate::types::OrchestrationControl) -> Self {
        self.control = ::std::option::Option::Some(input);
        self
    }
    /// <p>Status information about whether chat orchestration is activated or deactivated for your Amazon Q Business application.</p>
    pub fn set_control(mut self, input: ::std::option::Option<crate::types::OrchestrationControl>) -> Self {
        self.control = input;
        self
    }
    /// <p>Status information about whether chat orchestration is activated or deactivated for your Amazon Q Business application.</p>
    pub fn get_control(&self) -> &::std::option::Option<crate::types::OrchestrationControl> {
        &self.control
    }
    /// Consumes the builder and constructs a [`OrchestrationConfiguration`](crate::types::OrchestrationConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`control`](crate::types::builders::OrchestrationConfigurationBuilder::control)
    pub fn build(self) -> ::std::result::Result<crate::types::OrchestrationConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::OrchestrationConfiguration {
            control: self.control.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "control",
                    "control was not specified but it is required when building OrchestrationConfiguration",
                )
            })?,
        })
    }
}
