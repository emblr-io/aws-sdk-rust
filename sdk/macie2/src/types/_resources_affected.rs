// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides information about the resources that a finding applies to.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResourcesAffected {
    /// <p>The details of the S3 bucket that the finding applies to.</p>
    pub s3_bucket: ::std::option::Option<crate::types::S3Bucket>,
    /// <p>The details of the S3 object that the finding applies to.</p>
    pub s3_object: ::std::option::Option<crate::types::S3Object>,
}
impl ResourcesAffected {
    /// <p>The details of the S3 bucket that the finding applies to.</p>
    pub fn s3_bucket(&self) -> ::std::option::Option<&crate::types::S3Bucket> {
        self.s3_bucket.as_ref()
    }
    /// <p>The details of the S3 object that the finding applies to.</p>
    pub fn s3_object(&self) -> ::std::option::Option<&crate::types::S3Object> {
        self.s3_object.as_ref()
    }
}
impl ResourcesAffected {
    /// Creates a new builder-style object to manufacture [`ResourcesAffected`](crate::types::ResourcesAffected).
    pub fn builder() -> crate::types::builders::ResourcesAffectedBuilder {
        crate::types::builders::ResourcesAffectedBuilder::default()
    }
}

/// A builder for [`ResourcesAffected`](crate::types::ResourcesAffected).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResourcesAffectedBuilder {
    pub(crate) s3_bucket: ::std::option::Option<crate::types::S3Bucket>,
    pub(crate) s3_object: ::std::option::Option<crate::types::S3Object>,
}
impl ResourcesAffectedBuilder {
    /// <p>The details of the S3 bucket that the finding applies to.</p>
    pub fn s3_bucket(mut self, input: crate::types::S3Bucket) -> Self {
        self.s3_bucket = ::std::option::Option::Some(input);
        self
    }
    /// <p>The details of the S3 bucket that the finding applies to.</p>
    pub fn set_s3_bucket(mut self, input: ::std::option::Option<crate::types::S3Bucket>) -> Self {
        self.s3_bucket = input;
        self
    }
    /// <p>The details of the S3 bucket that the finding applies to.</p>
    pub fn get_s3_bucket(&self) -> &::std::option::Option<crate::types::S3Bucket> {
        &self.s3_bucket
    }
    /// <p>The details of the S3 object that the finding applies to.</p>
    pub fn s3_object(mut self, input: crate::types::S3Object) -> Self {
        self.s3_object = ::std::option::Option::Some(input);
        self
    }
    /// <p>The details of the S3 object that the finding applies to.</p>
    pub fn set_s3_object(mut self, input: ::std::option::Option<crate::types::S3Object>) -> Self {
        self.s3_object = input;
        self
    }
    /// <p>The details of the S3 object that the finding applies to.</p>
    pub fn get_s3_object(&self) -> &::std::option::Option<crate::types::S3Object> {
        &self.s3_object
    }
    /// Consumes the builder and constructs a [`ResourcesAffected`](crate::types::ResourcesAffected).
    pub fn build(self) -> crate::types::ResourcesAffected {
        crate::types::ResourcesAffected {
            s3_bucket: self.s3_bucket,
            s3_object: self.s3_object,
        }
    }
}
