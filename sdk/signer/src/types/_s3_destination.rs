// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The name and prefix of the Amazon S3 bucket where AWS Signer saves your signed objects.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct S3Destination {
    /// <p>Name of the S3 bucket.</p>
    pub bucket_name: ::std::option::Option<::std::string::String>,
    /// <p>An S3 prefix that you can use to limit responses to those that begin with the specified prefix.</p>
    pub prefix: ::std::option::Option<::std::string::String>,
}
impl S3Destination {
    /// <p>Name of the S3 bucket.</p>
    pub fn bucket_name(&self) -> ::std::option::Option<&str> {
        self.bucket_name.as_deref()
    }
    /// <p>An S3 prefix that you can use to limit responses to those that begin with the specified prefix.</p>
    pub fn prefix(&self) -> ::std::option::Option<&str> {
        self.prefix.as_deref()
    }
}
impl S3Destination {
    /// Creates a new builder-style object to manufacture [`S3Destination`](crate::types::S3Destination).
    pub fn builder() -> crate::types::builders::S3DestinationBuilder {
        crate::types::builders::S3DestinationBuilder::default()
    }
}

/// A builder for [`S3Destination`](crate::types::S3Destination).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct S3DestinationBuilder {
    pub(crate) bucket_name: ::std::option::Option<::std::string::String>,
    pub(crate) prefix: ::std::option::Option<::std::string::String>,
}
impl S3DestinationBuilder {
    /// <p>Name of the S3 bucket.</p>
    pub fn bucket_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bucket_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of the S3 bucket.</p>
    pub fn set_bucket_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bucket_name = input;
        self
    }
    /// <p>Name of the S3 bucket.</p>
    pub fn get_bucket_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.bucket_name
    }
    /// <p>An S3 prefix that you can use to limit responses to those that begin with the specified prefix.</p>
    pub fn prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An S3 prefix that you can use to limit responses to those that begin with the specified prefix.</p>
    pub fn set_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.prefix = input;
        self
    }
    /// <p>An S3 prefix that you can use to limit responses to those that begin with the specified prefix.</p>
    pub fn get_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.prefix
    }
    /// Consumes the builder and constructs a [`S3Destination`](crate::types::S3Destination).
    pub fn build(self) -> crate::types::S3Destination {
        crate::types::S3Destination {
            bucket_name: self.bucket_name,
            prefix: self.prefix,
        }
    }
}
