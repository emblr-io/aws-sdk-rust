// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>CloudFront origin access identity.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CloudFrontOriginAccessIdentity {
    /// <p>The ID for the origin access identity, for example, <code>E74FTE3AJFJ256A</code>.</p>
    pub id: ::std::string::String,
    /// <p>The Amazon S3 canonical user ID for the origin access identity, used when giving the origin access identity read permission to an object in Amazon S3.</p>
    pub s3_canonical_user_id: ::std::string::String,
    /// <p>The current configuration information for the identity.</p>
    pub cloud_front_origin_access_identity_config: ::std::option::Option<crate::types::CloudFrontOriginAccessIdentityConfig>,
}
impl CloudFrontOriginAccessIdentity {
    /// <p>The ID for the origin access identity, for example, <code>E74FTE3AJFJ256A</code>.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>The Amazon S3 canonical user ID for the origin access identity, used when giving the origin access identity read permission to an object in Amazon S3.</p>
    pub fn s3_canonical_user_id(&self) -> &str {
        use std::ops::Deref;
        self.s3_canonical_user_id.deref()
    }
    /// <p>The current configuration information for the identity.</p>
    pub fn cloud_front_origin_access_identity_config(&self) -> ::std::option::Option<&crate::types::CloudFrontOriginAccessIdentityConfig> {
        self.cloud_front_origin_access_identity_config.as_ref()
    }
}
impl CloudFrontOriginAccessIdentity {
    /// Creates a new builder-style object to manufacture [`CloudFrontOriginAccessIdentity`](crate::types::CloudFrontOriginAccessIdentity).
    pub fn builder() -> crate::types::builders::CloudFrontOriginAccessIdentityBuilder {
        crate::types::builders::CloudFrontOriginAccessIdentityBuilder::default()
    }
}

/// A builder for [`CloudFrontOriginAccessIdentity`](crate::types::CloudFrontOriginAccessIdentity).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CloudFrontOriginAccessIdentityBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) s3_canonical_user_id: ::std::option::Option<::std::string::String>,
    pub(crate) cloud_front_origin_access_identity_config: ::std::option::Option<crate::types::CloudFrontOriginAccessIdentityConfig>,
}
impl CloudFrontOriginAccessIdentityBuilder {
    /// <p>The ID for the origin access identity, for example, <code>E74FTE3AJFJ256A</code>.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID for the origin access identity, for example, <code>E74FTE3AJFJ256A</code>.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID for the origin access identity, for example, <code>E74FTE3AJFJ256A</code>.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The Amazon S3 canonical user ID for the origin access identity, used when giving the origin access identity read permission to an object in Amazon S3.</p>
    /// This field is required.
    pub fn s3_canonical_user_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_canonical_user_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon S3 canonical user ID for the origin access identity, used when giving the origin access identity read permission to an object in Amazon S3.</p>
    pub fn set_s3_canonical_user_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_canonical_user_id = input;
        self
    }
    /// <p>The Amazon S3 canonical user ID for the origin access identity, used when giving the origin access identity read permission to an object in Amazon S3.</p>
    pub fn get_s3_canonical_user_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_canonical_user_id
    }
    /// <p>The current configuration information for the identity.</p>
    pub fn cloud_front_origin_access_identity_config(mut self, input: crate::types::CloudFrontOriginAccessIdentityConfig) -> Self {
        self.cloud_front_origin_access_identity_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current configuration information for the identity.</p>
    pub fn set_cloud_front_origin_access_identity_config(
        mut self,
        input: ::std::option::Option<crate::types::CloudFrontOriginAccessIdentityConfig>,
    ) -> Self {
        self.cloud_front_origin_access_identity_config = input;
        self
    }
    /// <p>The current configuration information for the identity.</p>
    pub fn get_cloud_front_origin_access_identity_config(&self) -> &::std::option::Option<crate::types::CloudFrontOriginAccessIdentityConfig> {
        &self.cloud_front_origin_access_identity_config
    }
    /// Consumes the builder and constructs a [`CloudFrontOriginAccessIdentity`](crate::types::CloudFrontOriginAccessIdentity).
    /// This method will fail if any of the following fields are not set:
    /// - [`id`](crate::types::builders::CloudFrontOriginAccessIdentityBuilder::id)
    /// - [`s3_canonical_user_id`](crate::types::builders::CloudFrontOriginAccessIdentityBuilder::s3_canonical_user_id)
    pub fn build(self) -> ::std::result::Result<crate::types::CloudFrontOriginAccessIdentity, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CloudFrontOriginAccessIdentity {
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building CloudFrontOriginAccessIdentity",
                )
            })?,
            s3_canonical_user_id: self.s3_canonical_user_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "s3_canonical_user_id",
                    "s3_canonical_user_id was not specified but it is required when building CloudFrontOriginAccessIdentity",
                )
            })?,
            cloud_front_origin_access_identity_config: self.cloud_front_origin_access_identity_config,
        })
    }
}
