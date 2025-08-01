// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Gives a detailed description of failed messages in the batch.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchResultErrorEntry {
    /// <p>The <code>Id</code> of an entry in a batch request</p>
    pub id: ::std::string::String,
    /// <p>An error code representing why the action failed on this entry.</p>
    pub code: ::std::string::String,
    /// <p>A message explaining why the action failed on this entry.</p>
    pub message: ::std::option::Option<::std::string::String>,
    /// <p>Specifies whether the error happened due to the caller of the batch API action.</p>
    pub sender_fault: bool,
}
impl BatchResultErrorEntry {
    /// <p>The <code>Id</code> of an entry in a batch request</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>An error code representing why the action failed on this entry.</p>
    pub fn code(&self) -> &str {
        use std::ops::Deref;
        self.code.deref()
    }
    /// <p>A message explaining why the action failed on this entry.</p>
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
    /// <p>Specifies whether the error happened due to the caller of the batch API action.</p>
    pub fn sender_fault(&self) -> bool {
        self.sender_fault
    }
}
impl BatchResultErrorEntry {
    /// Creates a new builder-style object to manufacture [`BatchResultErrorEntry`](crate::types::BatchResultErrorEntry).
    pub fn builder() -> crate::types::builders::BatchResultErrorEntryBuilder {
        crate::types::builders::BatchResultErrorEntryBuilder::default()
    }
}

/// A builder for [`BatchResultErrorEntry`](crate::types::BatchResultErrorEntry).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchResultErrorEntryBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) code: ::std::option::Option<::std::string::String>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
    pub(crate) sender_fault: ::std::option::Option<bool>,
}
impl BatchResultErrorEntryBuilder {
    /// <p>The <code>Id</code> of an entry in a batch request</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>Id</code> of an entry in a batch request</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The <code>Id</code> of an entry in a batch request</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>An error code representing why the action failed on this entry.</p>
    /// This field is required.
    pub fn code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An error code representing why the action failed on this entry.</p>
    pub fn set_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.code = input;
        self
    }
    /// <p>An error code representing why the action failed on this entry.</p>
    pub fn get_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.code
    }
    /// <p>A message explaining why the action failed on this entry.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A message explaining why the action failed on this entry.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>A message explaining why the action failed on this entry.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// <p>Specifies whether the error happened due to the caller of the batch API action.</p>
    /// This field is required.
    pub fn sender_fault(mut self, input: bool) -> Self {
        self.sender_fault = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether the error happened due to the caller of the batch API action.</p>
    pub fn set_sender_fault(mut self, input: ::std::option::Option<bool>) -> Self {
        self.sender_fault = input;
        self
    }
    /// <p>Specifies whether the error happened due to the caller of the batch API action.</p>
    pub fn get_sender_fault(&self) -> &::std::option::Option<bool> {
        &self.sender_fault
    }
    /// Consumes the builder and constructs a [`BatchResultErrorEntry`](crate::types::BatchResultErrorEntry).
    /// This method will fail if any of the following fields are not set:
    /// - [`id`](crate::types::builders::BatchResultErrorEntryBuilder::id)
    /// - [`code`](crate::types::builders::BatchResultErrorEntryBuilder::code)
    pub fn build(self) -> ::std::result::Result<crate::types::BatchResultErrorEntry, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::BatchResultErrorEntry {
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building BatchResultErrorEntry",
                )
            })?,
            code: self.code.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "code",
                    "code was not specified but it is required when building BatchResultErrorEntry",
                )
            })?,
            message: self.message,
            sender_fault: self.sender_fault.unwrap_or_default(),
        })
    }
}
