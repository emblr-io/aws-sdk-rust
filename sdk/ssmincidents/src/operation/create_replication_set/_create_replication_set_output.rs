// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateReplicationSetOutput {
    /// <p>The Amazon Resource Name (ARN) of the replication set.</p>
    pub arn: ::std::string::String,
    _request_id: Option<String>,
}
impl CreateReplicationSetOutput {
    /// <p>The Amazon Resource Name (ARN) of the replication set.</p>
    pub fn arn(&self) -> &str {
        use std::ops::Deref;
        self.arn.deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateReplicationSetOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateReplicationSetOutput {
    /// Creates a new builder-style object to manufacture [`CreateReplicationSetOutput`](crate::operation::create_replication_set::CreateReplicationSetOutput).
    pub fn builder() -> crate::operation::create_replication_set::builders::CreateReplicationSetOutputBuilder {
        crate::operation::create_replication_set::builders::CreateReplicationSetOutputBuilder::default()
    }
}

/// A builder for [`CreateReplicationSetOutput`](crate::operation::create_replication_set::CreateReplicationSetOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateReplicationSetOutputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateReplicationSetOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the replication set.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the replication set.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the replication set.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateReplicationSetOutput`](crate::operation::create_replication_set::CreateReplicationSetOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`arn`](crate::operation::create_replication_set::builders::CreateReplicationSetOutputBuilder::arn)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_replication_set::CreateReplicationSetOutput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::create_replication_set::CreateReplicationSetOutput {
            arn: self.arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "arn",
                    "arn was not specified but it is required when building CreateReplicationSetOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
