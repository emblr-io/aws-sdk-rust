// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Origin access identity configuration. Send a <code>GET</code> request to the <code>/<i>CloudFront API version</i>/CloudFront/identity ID/config</code> resource.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CloudFrontOriginAccessIdentityConfig {
    /// <p>A unique value (for example, a date-time stamp) that ensures that the request can't be replayed.</p>
    /// <p>If the value of <code>CallerReference</code> is new (regardless of the content of the <code>CloudFrontOriginAccessIdentityConfig</code> object), a new origin access identity is created.</p>
    /// <p>If the <code>CallerReference</code> is a value already sent in a previous identity request, and the content of the <code>CloudFrontOriginAccessIdentityConfig</code> is identical to the original request (ignoring white space), the response includes the same information returned to the original request.</p>
    /// <p>If the <code>CallerReference</code> is a value you already sent in a previous request to create an identity, but the content of the <code>CloudFrontOriginAccessIdentityConfig</code> is different from the original request, CloudFront returns a <code>CloudFrontOriginAccessIdentityAlreadyExists</code> error.</p>
    pub caller_reference: ::std::string::String,
    /// <p>A comment to describe the origin access identity. The comment cannot be longer than 128 characters.</p>
    pub comment: ::std::string::String,
}
impl CloudFrontOriginAccessIdentityConfig {
    /// <p>A unique value (for example, a date-time stamp) that ensures that the request can't be replayed.</p>
    /// <p>If the value of <code>CallerReference</code> is new (regardless of the content of the <code>CloudFrontOriginAccessIdentityConfig</code> object), a new origin access identity is created.</p>
    /// <p>If the <code>CallerReference</code> is a value already sent in a previous identity request, and the content of the <code>CloudFrontOriginAccessIdentityConfig</code> is identical to the original request (ignoring white space), the response includes the same information returned to the original request.</p>
    /// <p>If the <code>CallerReference</code> is a value you already sent in a previous request to create an identity, but the content of the <code>CloudFrontOriginAccessIdentityConfig</code> is different from the original request, CloudFront returns a <code>CloudFrontOriginAccessIdentityAlreadyExists</code> error.</p>
    pub fn caller_reference(&self) -> &str {
        use std::ops::Deref;
        self.caller_reference.deref()
    }
    /// <p>A comment to describe the origin access identity. The comment cannot be longer than 128 characters.</p>
    pub fn comment(&self) -> &str {
        use std::ops::Deref;
        self.comment.deref()
    }
}
impl CloudFrontOriginAccessIdentityConfig {
    /// Creates a new builder-style object to manufacture [`CloudFrontOriginAccessIdentityConfig`](crate::types::CloudFrontOriginAccessIdentityConfig).
    pub fn builder() -> crate::types::builders::CloudFrontOriginAccessIdentityConfigBuilder {
        crate::types::builders::CloudFrontOriginAccessIdentityConfigBuilder::default()
    }
}

/// A builder for [`CloudFrontOriginAccessIdentityConfig`](crate::types::CloudFrontOriginAccessIdentityConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CloudFrontOriginAccessIdentityConfigBuilder {
    pub(crate) caller_reference: ::std::option::Option<::std::string::String>,
    pub(crate) comment: ::std::option::Option<::std::string::String>,
}
impl CloudFrontOriginAccessIdentityConfigBuilder {
    /// <p>A unique value (for example, a date-time stamp) that ensures that the request can't be replayed.</p>
    /// <p>If the value of <code>CallerReference</code> is new (regardless of the content of the <code>CloudFrontOriginAccessIdentityConfig</code> object), a new origin access identity is created.</p>
    /// <p>If the <code>CallerReference</code> is a value already sent in a previous identity request, and the content of the <code>CloudFrontOriginAccessIdentityConfig</code> is identical to the original request (ignoring white space), the response includes the same information returned to the original request.</p>
    /// <p>If the <code>CallerReference</code> is a value you already sent in a previous request to create an identity, but the content of the <code>CloudFrontOriginAccessIdentityConfig</code> is different from the original request, CloudFront returns a <code>CloudFrontOriginAccessIdentityAlreadyExists</code> error.</p>
    /// This field is required.
    pub fn caller_reference(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.caller_reference = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique value (for example, a date-time stamp) that ensures that the request can't be replayed.</p>
    /// <p>If the value of <code>CallerReference</code> is new (regardless of the content of the <code>CloudFrontOriginAccessIdentityConfig</code> object), a new origin access identity is created.</p>
    /// <p>If the <code>CallerReference</code> is a value already sent in a previous identity request, and the content of the <code>CloudFrontOriginAccessIdentityConfig</code> is identical to the original request (ignoring white space), the response includes the same information returned to the original request.</p>
    /// <p>If the <code>CallerReference</code> is a value you already sent in a previous request to create an identity, but the content of the <code>CloudFrontOriginAccessIdentityConfig</code> is different from the original request, CloudFront returns a <code>CloudFrontOriginAccessIdentityAlreadyExists</code> error.</p>
    pub fn set_caller_reference(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.caller_reference = input;
        self
    }
    /// <p>A unique value (for example, a date-time stamp) that ensures that the request can't be replayed.</p>
    /// <p>If the value of <code>CallerReference</code> is new (regardless of the content of the <code>CloudFrontOriginAccessIdentityConfig</code> object), a new origin access identity is created.</p>
    /// <p>If the <code>CallerReference</code> is a value already sent in a previous identity request, and the content of the <code>CloudFrontOriginAccessIdentityConfig</code> is identical to the original request (ignoring white space), the response includes the same information returned to the original request.</p>
    /// <p>If the <code>CallerReference</code> is a value you already sent in a previous request to create an identity, but the content of the <code>CloudFrontOriginAccessIdentityConfig</code> is different from the original request, CloudFront returns a <code>CloudFrontOriginAccessIdentityAlreadyExists</code> error.</p>
    pub fn get_caller_reference(&self) -> &::std::option::Option<::std::string::String> {
        &self.caller_reference
    }
    /// <p>A comment to describe the origin access identity. The comment cannot be longer than 128 characters.</p>
    /// This field is required.
    pub fn comment(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.comment = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A comment to describe the origin access identity. The comment cannot be longer than 128 characters.</p>
    pub fn set_comment(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.comment = input;
        self
    }
    /// <p>A comment to describe the origin access identity. The comment cannot be longer than 128 characters.</p>
    pub fn get_comment(&self) -> &::std::option::Option<::std::string::String> {
        &self.comment
    }
    /// Consumes the builder and constructs a [`CloudFrontOriginAccessIdentityConfig`](crate::types::CloudFrontOriginAccessIdentityConfig).
    /// This method will fail if any of the following fields are not set:
    /// - [`caller_reference`](crate::types::builders::CloudFrontOriginAccessIdentityConfigBuilder::caller_reference)
    /// - [`comment`](crate::types::builders::CloudFrontOriginAccessIdentityConfigBuilder::comment)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::CloudFrontOriginAccessIdentityConfig, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CloudFrontOriginAccessIdentityConfig {
            caller_reference: self.caller_reference.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "caller_reference",
                    "caller_reference was not specified but it is required when building CloudFrontOriginAccessIdentityConfig",
                )
            })?,
            comment: self.comment.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "comment",
                    "comment was not specified but it is required when building CloudFrontOriginAccessIdentityConfig",
                )
            })?,
        })
    }
}
