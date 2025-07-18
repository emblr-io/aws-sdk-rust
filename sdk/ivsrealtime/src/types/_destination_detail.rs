// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Complex data type that defines destination-detail objects.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DestinationDetail {
    /// <p>An S3 detail object to return information about the S3 destination.</p>
    pub s3: ::std::option::Option<crate::types::S3Detail>,
}
impl DestinationDetail {
    /// <p>An S3 detail object to return information about the S3 destination.</p>
    pub fn s3(&self) -> ::std::option::Option<&crate::types::S3Detail> {
        self.s3.as_ref()
    }
}
impl DestinationDetail {
    /// Creates a new builder-style object to manufacture [`DestinationDetail`](crate::types::DestinationDetail).
    pub fn builder() -> crate::types::builders::DestinationDetailBuilder {
        crate::types::builders::DestinationDetailBuilder::default()
    }
}

/// A builder for [`DestinationDetail`](crate::types::DestinationDetail).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DestinationDetailBuilder {
    pub(crate) s3: ::std::option::Option<crate::types::S3Detail>,
}
impl DestinationDetailBuilder {
    /// <p>An S3 detail object to return information about the S3 destination.</p>
    pub fn s3(mut self, input: crate::types::S3Detail) -> Self {
        self.s3 = ::std::option::Option::Some(input);
        self
    }
    /// <p>An S3 detail object to return information about the S3 destination.</p>
    pub fn set_s3(mut self, input: ::std::option::Option<crate::types::S3Detail>) -> Self {
        self.s3 = input;
        self
    }
    /// <p>An S3 detail object to return information about the S3 destination.</p>
    pub fn get_s3(&self) -> &::std::option::Option<crate::types::S3Detail> {
        &self.s3
    }
    /// Consumes the builder and constructs a [`DestinationDetail`](crate::types::DestinationDetail).
    pub fn build(self) -> crate::types::DestinationDetail {
        crate::types::DestinationDetail { s3: self.s3 }
    }
}
