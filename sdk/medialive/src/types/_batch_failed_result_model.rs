// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Details from a failed operation
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchFailedResultModel {
    /// ARN of the resource
    pub arn: ::std::option::Option<::std::string::String>,
    /// Error code for the failed operation
    pub code: ::std::option::Option<::std::string::String>,
    /// ID of the resource
    pub id: ::std::option::Option<::std::string::String>,
    /// Error message for the failed operation
    pub message: ::std::option::Option<::std::string::String>,
}
impl BatchFailedResultModel {
    /// ARN of the resource
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// Error code for the failed operation
    pub fn code(&self) -> ::std::option::Option<&str> {
        self.code.as_deref()
    }
    /// ID of the resource
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// Error message for the failed operation
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl BatchFailedResultModel {
    /// Creates a new builder-style object to manufacture [`BatchFailedResultModel`](crate::types::BatchFailedResultModel).
    pub fn builder() -> crate::types::builders::BatchFailedResultModelBuilder {
        crate::types::builders::BatchFailedResultModelBuilder::default()
    }
}

/// A builder for [`BatchFailedResultModel`](crate::types::BatchFailedResultModel).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchFailedResultModelBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) code: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
}
impl BatchFailedResultModelBuilder {
    /// ARN of the resource
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// ARN of the resource
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// ARN of the resource
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// Error code for the failed operation
    pub fn code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.code = ::std::option::Option::Some(input.into());
        self
    }
    /// Error code for the failed operation
    pub fn set_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.code = input;
        self
    }
    /// Error code for the failed operation
    pub fn get_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.code
    }
    /// ID of the resource
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// ID of the resource
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// ID of the resource
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// Error message for the failed operation
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// Error message for the failed operation
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// Error message for the failed operation
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// Consumes the builder and constructs a [`BatchFailedResultModel`](crate::types::BatchFailedResultModel).
    pub fn build(self) -> crate::types::BatchFailedResultModel {
        crate::types::BatchFailedResultModel {
            arn: self.arn,
            code: self.code,
            id: self.id,
            message: self.message,
        }
    }
}
