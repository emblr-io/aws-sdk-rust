// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides details about assigned variables in an execution history event.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssignedVariablesDetails {
    /// <p>Indicates whether assigned variables were truncated in the response. Always <code>false</code> for API calls. In CloudWatch logs, the value will be true if the data is truncated due to size limits.</p>
    pub truncated: bool,
}
impl AssignedVariablesDetails {
    /// <p>Indicates whether assigned variables were truncated in the response. Always <code>false</code> for API calls. In CloudWatch logs, the value will be true if the data is truncated due to size limits.</p>
    pub fn truncated(&self) -> bool {
        self.truncated
    }
}
impl AssignedVariablesDetails {
    /// Creates a new builder-style object to manufacture [`AssignedVariablesDetails`](crate::types::AssignedVariablesDetails).
    pub fn builder() -> crate::types::builders::AssignedVariablesDetailsBuilder {
        crate::types::builders::AssignedVariablesDetailsBuilder::default()
    }
}

/// A builder for [`AssignedVariablesDetails`](crate::types::AssignedVariablesDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssignedVariablesDetailsBuilder {
    pub(crate) truncated: ::std::option::Option<bool>,
}
impl AssignedVariablesDetailsBuilder {
    /// <p>Indicates whether assigned variables were truncated in the response. Always <code>false</code> for API calls. In CloudWatch logs, the value will be true if the data is truncated due to size limits.</p>
    pub fn truncated(mut self, input: bool) -> Self {
        self.truncated = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether assigned variables were truncated in the response. Always <code>false</code> for API calls. In CloudWatch logs, the value will be true if the data is truncated due to size limits.</p>
    pub fn set_truncated(mut self, input: ::std::option::Option<bool>) -> Self {
        self.truncated = input;
        self
    }
    /// <p>Indicates whether assigned variables were truncated in the response. Always <code>false</code> for API calls. In CloudWatch logs, the value will be true if the data is truncated due to size limits.</p>
    pub fn get_truncated(&self) -> &::std::option::Option<bool> {
        &self.truncated
    }
    /// Consumes the builder and constructs a [`AssignedVariablesDetails`](crate::types::AssignedVariablesDetails).
    pub fn build(self) -> crate::types::AssignedVariablesDetails {
        crate::types::AssignedVariablesDetails {
            truncated: self.truncated.unwrap_or_default(),
        }
    }
}
