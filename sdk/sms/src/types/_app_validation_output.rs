// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Output from validating an application.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AppValidationOutput {
    /// <p>Output from using SSM to validate the application.</p>
    pub ssm_output: ::std::option::Option<crate::types::SsmOutput>,
}
impl AppValidationOutput {
    /// <p>Output from using SSM to validate the application.</p>
    pub fn ssm_output(&self) -> ::std::option::Option<&crate::types::SsmOutput> {
        self.ssm_output.as_ref()
    }
}
impl AppValidationOutput {
    /// Creates a new builder-style object to manufacture [`AppValidationOutput`](crate::types::AppValidationOutput).
    pub fn builder() -> crate::types::builders::AppValidationOutputBuilder {
        crate::types::builders::AppValidationOutputBuilder::default()
    }
}

/// A builder for [`AppValidationOutput`](crate::types::AppValidationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AppValidationOutputBuilder {
    pub(crate) ssm_output: ::std::option::Option<crate::types::SsmOutput>,
}
impl AppValidationOutputBuilder {
    /// <p>Output from using SSM to validate the application.</p>
    pub fn ssm_output(mut self, input: crate::types::SsmOutput) -> Self {
        self.ssm_output = ::std::option::Option::Some(input);
        self
    }
    /// <p>Output from using SSM to validate the application.</p>
    pub fn set_ssm_output(mut self, input: ::std::option::Option<crate::types::SsmOutput>) -> Self {
        self.ssm_output = input;
        self
    }
    /// <p>Output from using SSM to validate the application.</p>
    pub fn get_ssm_output(&self) -> &::std::option::Option<crate::types::SsmOutput> {
        &self.ssm_output
    }
    /// Consumes the builder and constructs a [`AppValidationOutput`](crate::types::AppValidationOutput).
    pub fn build(self) -> crate::types::AppValidationOutput {
        crate::types::AppValidationOutput { ssm_output: self.ssm_output }
    }
}
