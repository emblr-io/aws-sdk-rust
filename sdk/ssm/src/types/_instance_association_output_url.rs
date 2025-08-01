// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The URL of S3 bucket where you want to store the results of this request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InstanceAssociationOutputUrl {
    /// <p>The URL of S3 bucket where you want to store the results of this request.</p>
    pub s3_output_url: ::std::option::Option<crate::types::S3OutputUrl>,
}
impl InstanceAssociationOutputUrl {
    /// <p>The URL of S3 bucket where you want to store the results of this request.</p>
    pub fn s3_output_url(&self) -> ::std::option::Option<&crate::types::S3OutputUrl> {
        self.s3_output_url.as_ref()
    }
}
impl InstanceAssociationOutputUrl {
    /// Creates a new builder-style object to manufacture [`InstanceAssociationOutputUrl`](crate::types::InstanceAssociationOutputUrl).
    pub fn builder() -> crate::types::builders::InstanceAssociationOutputUrlBuilder {
        crate::types::builders::InstanceAssociationOutputUrlBuilder::default()
    }
}

/// A builder for [`InstanceAssociationOutputUrl`](crate::types::InstanceAssociationOutputUrl).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InstanceAssociationOutputUrlBuilder {
    pub(crate) s3_output_url: ::std::option::Option<crate::types::S3OutputUrl>,
}
impl InstanceAssociationOutputUrlBuilder {
    /// <p>The URL of S3 bucket where you want to store the results of this request.</p>
    pub fn s3_output_url(mut self, input: crate::types::S3OutputUrl) -> Self {
        self.s3_output_url = ::std::option::Option::Some(input);
        self
    }
    /// <p>The URL of S3 bucket where you want to store the results of this request.</p>
    pub fn set_s3_output_url(mut self, input: ::std::option::Option<crate::types::S3OutputUrl>) -> Self {
        self.s3_output_url = input;
        self
    }
    /// <p>The URL of S3 bucket where you want to store the results of this request.</p>
    pub fn get_s3_output_url(&self) -> &::std::option::Option<crate::types::S3OutputUrl> {
        &self.s3_output_url
    }
    /// Consumes the builder and constructs a [`InstanceAssociationOutputUrl`](crate::types::InstanceAssociationOutputUrl).
    pub fn build(self) -> crate::types::InstanceAssociationOutputUrl {
        crate::types::InstanceAssociationOutputUrl {
            s3_output_url: self.s3_output_url,
        }
    }
}
