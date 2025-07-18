// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the location of a validation script.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Source {
    /// <p>Location of an Amazon S3 object.</p>
    pub s3_location: ::std::option::Option<crate::types::S3Location>,
}
impl Source {
    /// <p>Location of an Amazon S3 object.</p>
    pub fn s3_location(&self) -> ::std::option::Option<&crate::types::S3Location> {
        self.s3_location.as_ref()
    }
}
impl Source {
    /// Creates a new builder-style object to manufacture [`Source`](crate::types::Source).
    pub fn builder() -> crate::types::builders::SourceBuilder {
        crate::types::builders::SourceBuilder::default()
    }
}

/// A builder for [`Source`](crate::types::Source).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SourceBuilder {
    pub(crate) s3_location: ::std::option::Option<crate::types::S3Location>,
}
impl SourceBuilder {
    /// <p>Location of an Amazon S3 object.</p>
    pub fn s3_location(mut self, input: crate::types::S3Location) -> Self {
        self.s3_location = ::std::option::Option::Some(input);
        self
    }
    /// <p>Location of an Amazon S3 object.</p>
    pub fn set_s3_location(mut self, input: ::std::option::Option<crate::types::S3Location>) -> Self {
        self.s3_location = input;
        self
    }
    /// <p>Location of an Amazon S3 object.</p>
    pub fn get_s3_location(&self) -> &::std::option::Option<crate::types::S3Location> {
        &self.s3_location
    }
    /// Consumes the builder and constructs a [`Source`](crate::types::Source).
    pub fn build(self) -> crate::types::Source {
        crate::types::Source {
            s3_location: self.s3_location,
        }
    }
}
