// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the state of a target network association.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociationStatus {
    /// <p>The state of the target network association.</p>
    pub code: ::std::option::Option<crate::types::AssociationStatusCode>,
    /// <p>A message about the status of the target network association, if applicable.</p>
    pub message: ::std::option::Option<::std::string::String>,
}
impl AssociationStatus {
    /// <p>The state of the target network association.</p>
    pub fn code(&self) -> ::std::option::Option<&crate::types::AssociationStatusCode> {
        self.code.as_ref()
    }
    /// <p>A message about the status of the target network association, if applicable.</p>
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl AssociationStatus {
    /// Creates a new builder-style object to manufacture [`AssociationStatus`](crate::types::AssociationStatus).
    pub fn builder() -> crate::types::builders::AssociationStatusBuilder {
        crate::types::builders::AssociationStatusBuilder::default()
    }
}

/// A builder for [`AssociationStatus`](crate::types::AssociationStatus).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociationStatusBuilder {
    pub(crate) code: ::std::option::Option<crate::types::AssociationStatusCode>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
}
impl AssociationStatusBuilder {
    /// <p>The state of the target network association.</p>
    pub fn code(mut self, input: crate::types::AssociationStatusCode) -> Self {
        self.code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The state of the target network association.</p>
    pub fn set_code(mut self, input: ::std::option::Option<crate::types::AssociationStatusCode>) -> Self {
        self.code = input;
        self
    }
    /// <p>The state of the target network association.</p>
    pub fn get_code(&self) -> &::std::option::Option<crate::types::AssociationStatusCode> {
        &self.code
    }
    /// <p>A message about the status of the target network association, if applicable.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A message about the status of the target network association, if applicable.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>A message about the status of the target network association, if applicable.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// Consumes the builder and constructs a [`AssociationStatus`](crate::types::AssociationStatus).
    pub fn build(self) -> crate::types::AssociationStatus {
        crate::types::AssociationStatus {
            code: self.code,
            message: self.message,
        }
    }
}
