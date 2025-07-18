// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteKeyInput {
    /// <p>The Amazon Resource Name (ARN) of the Key Value Store.</p>
    pub kvs_arn: ::std::option::Option<::std::string::String>,
    /// <p>The key to delete.</p>
    pub key: ::std::option::Option<::std::string::String>,
    /// <p>The current version (ETag) of the Key Value Store that you are deleting keys from, which you can get using DescribeKeyValueStore.</p>
    pub if_match: ::std::option::Option<::std::string::String>,
}
impl DeleteKeyInput {
    /// <p>The Amazon Resource Name (ARN) of the Key Value Store.</p>
    pub fn kvs_arn(&self) -> ::std::option::Option<&str> {
        self.kvs_arn.as_deref()
    }
    /// <p>The key to delete.</p>
    pub fn key(&self) -> ::std::option::Option<&str> {
        self.key.as_deref()
    }
    /// <p>The current version (ETag) of the Key Value Store that you are deleting keys from, which you can get using DescribeKeyValueStore.</p>
    pub fn if_match(&self) -> ::std::option::Option<&str> {
        self.if_match.as_deref()
    }
}
impl DeleteKeyInput {
    /// Creates a new builder-style object to manufacture [`DeleteKeyInput`](crate::operation::delete_key::DeleteKeyInput).
    pub fn builder() -> crate::operation::delete_key::builders::DeleteKeyInputBuilder {
        crate::operation::delete_key::builders::DeleteKeyInputBuilder::default()
    }
}

/// A builder for [`DeleteKeyInput`](crate::operation::delete_key::DeleteKeyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteKeyInputBuilder {
    pub(crate) kvs_arn: ::std::option::Option<::std::string::String>,
    pub(crate) key: ::std::option::Option<::std::string::String>,
    pub(crate) if_match: ::std::option::Option<::std::string::String>,
}
impl DeleteKeyInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the Key Value Store.</p>
    /// This field is required.
    pub fn kvs_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kvs_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Key Value Store.</p>
    pub fn set_kvs_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kvs_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Key Value Store.</p>
    pub fn get_kvs_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.kvs_arn
    }
    /// <p>The key to delete.</p>
    /// This field is required.
    pub fn key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The key to delete.</p>
    pub fn set_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key = input;
        self
    }
    /// <p>The key to delete.</p>
    pub fn get_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.key
    }
    /// <p>The current version (ETag) of the Key Value Store that you are deleting keys from, which you can get using DescribeKeyValueStore.</p>
    /// This field is required.
    pub fn if_match(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.if_match = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The current version (ETag) of the Key Value Store that you are deleting keys from, which you can get using DescribeKeyValueStore.</p>
    pub fn set_if_match(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.if_match = input;
        self
    }
    /// <p>The current version (ETag) of the Key Value Store that you are deleting keys from, which you can get using DescribeKeyValueStore.</p>
    pub fn get_if_match(&self) -> &::std::option::Option<::std::string::String> {
        &self.if_match
    }
    /// Consumes the builder and constructs a [`DeleteKeyInput`](crate::operation::delete_key::DeleteKeyInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::delete_key::DeleteKeyInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_key::DeleteKeyInput {
            kvs_arn: self.kvs_arn,
            key: self.key,
            if_match: self.if_match,
        })
    }
}
