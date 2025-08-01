// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteTypeOutput {
    /// <p>The unique identifier of the keyspace from which the type was deleted in the format of an Amazon Resource Name (ARN).</p>
    pub keyspace_arn: ::std::string::String,
    /// <p>The name of the type that was deleted.</p>
    pub type_name: ::std::string::String,
    _request_id: Option<String>,
}
impl DeleteTypeOutput {
    /// <p>The unique identifier of the keyspace from which the type was deleted in the format of an Amazon Resource Name (ARN).</p>
    pub fn keyspace_arn(&self) -> &str {
        use std::ops::Deref;
        self.keyspace_arn.deref()
    }
    /// <p>The name of the type that was deleted.</p>
    pub fn type_name(&self) -> &str {
        use std::ops::Deref;
        self.type_name.deref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteTypeOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteTypeOutput {
    /// Creates a new builder-style object to manufacture [`DeleteTypeOutput`](crate::operation::delete_type::DeleteTypeOutput).
    pub fn builder() -> crate::operation::delete_type::builders::DeleteTypeOutputBuilder {
        crate::operation::delete_type::builders::DeleteTypeOutputBuilder::default()
    }
}

/// A builder for [`DeleteTypeOutput`](crate::operation::delete_type::DeleteTypeOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteTypeOutputBuilder {
    pub(crate) keyspace_arn: ::std::option::Option<::std::string::String>,
    pub(crate) type_name: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeleteTypeOutputBuilder {
    /// <p>The unique identifier of the keyspace from which the type was deleted in the format of an Amazon Resource Name (ARN).</p>
    /// This field is required.
    pub fn keyspace_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.keyspace_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the keyspace from which the type was deleted in the format of an Amazon Resource Name (ARN).</p>
    pub fn set_keyspace_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.keyspace_arn = input;
        self
    }
    /// <p>The unique identifier of the keyspace from which the type was deleted in the format of an Amazon Resource Name (ARN).</p>
    pub fn get_keyspace_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.keyspace_arn
    }
    /// <p>The name of the type that was deleted.</p>
    /// This field is required.
    pub fn type_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.type_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the type that was deleted.</p>
    pub fn set_type_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.type_name = input;
        self
    }
    /// <p>The name of the type that was deleted.</p>
    pub fn get_type_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.type_name
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteTypeOutput`](crate::operation::delete_type::DeleteTypeOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`keyspace_arn`](crate::operation::delete_type::builders::DeleteTypeOutputBuilder::keyspace_arn)
    /// - [`type_name`](crate::operation::delete_type::builders::DeleteTypeOutputBuilder::type_name)
    pub fn build(self) -> ::std::result::Result<crate::operation::delete_type::DeleteTypeOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_type::DeleteTypeOutput {
            keyspace_arn: self.keyspace_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "keyspace_arn",
                    "keyspace_arn was not specified but it is required when building DeleteTypeOutput",
                )
            })?,
            type_name: self.type_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "type_name",
                    "type_name was not specified but it is required when building DeleteTypeOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
