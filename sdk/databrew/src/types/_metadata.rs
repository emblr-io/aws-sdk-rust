// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains additional resource information needed for specific datasets.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Metadata {
    /// <p>The Amazon Resource Name (ARN) associated with the dataset. Currently, DataBrew only supports ARNs from Amazon AppFlow.</p>
    pub source_arn: ::std::option::Option<::std::string::String>,
}
impl Metadata {
    /// <p>The Amazon Resource Name (ARN) associated with the dataset. Currently, DataBrew only supports ARNs from Amazon AppFlow.</p>
    pub fn source_arn(&self) -> ::std::option::Option<&str> {
        self.source_arn.as_deref()
    }
}
impl Metadata {
    /// Creates a new builder-style object to manufacture [`Metadata`](crate::types::Metadata).
    pub fn builder() -> crate::types::builders::MetadataBuilder {
        crate::types::builders::MetadataBuilder::default()
    }
}

/// A builder for [`Metadata`](crate::types::Metadata).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MetadataBuilder {
    pub(crate) source_arn: ::std::option::Option<::std::string::String>,
}
impl MetadataBuilder {
    /// <p>The Amazon Resource Name (ARN) associated with the dataset. Currently, DataBrew only supports ARNs from Amazon AppFlow.</p>
    pub fn source_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) associated with the dataset. Currently, DataBrew only supports ARNs from Amazon AppFlow.</p>
    pub fn set_source_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) associated with the dataset. Currently, DataBrew only supports ARNs from Amazon AppFlow.</p>
    pub fn get_source_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_arn
    }
    /// Consumes the builder and constructs a [`Metadata`](crate::types::Metadata).
    pub fn build(self) -> crate::types::Metadata {
        crate::types::Metadata { source_arn: self.source_arn }
    }
}
