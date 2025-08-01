// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct NotifyWhenUploadedInput {
    /// <p>The Amazon Resource Name (ARN) of the file share.</p>
    pub file_share_arn: ::std::option::Option<::std::string::String>,
}
impl NotifyWhenUploadedInput {
    /// <p>The Amazon Resource Name (ARN) of the file share.</p>
    pub fn file_share_arn(&self) -> ::std::option::Option<&str> {
        self.file_share_arn.as_deref()
    }
}
impl NotifyWhenUploadedInput {
    /// Creates a new builder-style object to manufacture [`NotifyWhenUploadedInput`](crate::operation::notify_when_uploaded::NotifyWhenUploadedInput).
    pub fn builder() -> crate::operation::notify_when_uploaded::builders::NotifyWhenUploadedInputBuilder {
        crate::operation::notify_when_uploaded::builders::NotifyWhenUploadedInputBuilder::default()
    }
}

/// A builder for [`NotifyWhenUploadedInput`](crate::operation::notify_when_uploaded::NotifyWhenUploadedInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct NotifyWhenUploadedInputBuilder {
    pub(crate) file_share_arn: ::std::option::Option<::std::string::String>,
}
impl NotifyWhenUploadedInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the file share.</p>
    /// This field is required.
    pub fn file_share_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.file_share_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the file share.</p>
    pub fn set_file_share_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.file_share_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the file share.</p>
    pub fn get_file_share_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.file_share_arn
    }
    /// Consumes the builder and constructs a [`NotifyWhenUploadedInput`](crate::operation::notify_when_uploaded::NotifyWhenUploadedInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::notify_when_uploaded::NotifyWhenUploadedInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::notify_when_uploaded::NotifyWhenUploadedInput {
            file_share_arn: self.file_share_arn,
        })
    }
}
