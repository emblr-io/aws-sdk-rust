// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Indicates the reason that the association deployment failed, including the error code and error message.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociationStateReason {
    /// <p>The error code of the association deployment failure.</p>
    pub error_code: ::std::option::Option<crate::types::AssociationErrorCode>,
    /// <p>The error message of the association deployment failure.</p>
    pub error_message: ::std::option::Option<::std::string::String>,
}
impl AssociationStateReason {
    /// <p>The error code of the association deployment failure.</p>
    pub fn error_code(&self) -> ::std::option::Option<&crate::types::AssociationErrorCode> {
        self.error_code.as_ref()
    }
    /// <p>The error message of the association deployment failure.</p>
    pub fn error_message(&self) -> ::std::option::Option<&str> {
        self.error_message.as_deref()
    }
}
impl AssociationStateReason {
    /// Creates a new builder-style object to manufacture [`AssociationStateReason`](crate::types::AssociationStateReason).
    pub fn builder() -> crate::types::builders::AssociationStateReasonBuilder {
        crate::types::builders::AssociationStateReasonBuilder::default()
    }
}

/// A builder for [`AssociationStateReason`](crate::types::AssociationStateReason).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociationStateReasonBuilder {
    pub(crate) error_code: ::std::option::Option<crate::types::AssociationErrorCode>,
    pub(crate) error_message: ::std::option::Option<::std::string::String>,
}
impl AssociationStateReasonBuilder {
    /// <p>The error code of the association deployment failure.</p>
    pub fn error_code(mut self, input: crate::types::AssociationErrorCode) -> Self {
        self.error_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The error code of the association deployment failure.</p>
    pub fn set_error_code(mut self, input: ::std::option::Option<crate::types::AssociationErrorCode>) -> Self {
        self.error_code = input;
        self
    }
    /// <p>The error code of the association deployment failure.</p>
    pub fn get_error_code(&self) -> &::std::option::Option<crate::types::AssociationErrorCode> {
        &self.error_code
    }
    /// <p>The error message of the association deployment failure.</p>
    pub fn error_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The error message of the association deployment failure.</p>
    pub fn set_error_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_message = input;
        self
    }
    /// <p>The error message of the association deployment failure.</p>
    pub fn get_error_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_message
    }
    /// Consumes the builder and constructs a [`AssociationStateReason`](crate::types::AssociationStateReason).
    pub fn build(self) -> crate::types::AssociationStateReason {
        crate::types::AssociationStateReason {
            error_code: self.error_code,
            error_message: self.error_message,
        }
    }
}
