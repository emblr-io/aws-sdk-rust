// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpgradeReviewTemplateLensReviewInput {
    /// <p>The ARN of the review template.</p>
    pub template_arn: ::std::option::Option<::std::string::String>,
    /// <p>The alias of the lens.</p>
    /// <p>For Amazon Web Services official lenses, this is either the lens alias, such as <code>serverless</code>, or the lens ARN, such as <code>arn:aws:wellarchitected:us-east-1::lens/serverless</code>. Note that some operations (such as ExportLens and CreateLensShare) are not permitted on Amazon Web Services official lenses.</p>
    /// <p>For custom lenses, this is the lens ARN, such as <code>arn:aws:wellarchitected:us-west-2:123456789012:lens/0123456789abcdef01234567890abcdef</code>.</p>
    /// <p>Each lens is identified by its <code>LensSummary$LensAlias</code>.</p>
    pub lens_alias: ::std::option::Option<::std::string::String>,
    /// <p>A unique case-sensitive string used to ensure that this request is idempotent (executes only once).</p>
    /// <p>You should not reuse the same token for other requests. If you retry a request with the same client request token and the same parameters after the original request has completed successfully, the result of the original request is returned.</p><important>
    /// <p>This token is listed as required, however, if you do not specify it, the Amazon Web Services SDKs automatically generate one for you. If you are not using the Amazon Web Services SDK or the CLI, you must provide this token or the request will fail.</p>
    /// </important>
    pub client_request_token: ::std::option::Option<::std::string::String>,
}
impl UpgradeReviewTemplateLensReviewInput {
    /// <p>The ARN of the review template.</p>
    pub fn template_arn(&self) -> ::std::option::Option<&str> {
        self.template_arn.as_deref()
    }
    /// <p>The alias of the lens.</p>
    /// <p>For Amazon Web Services official lenses, this is either the lens alias, such as <code>serverless</code>, or the lens ARN, such as <code>arn:aws:wellarchitected:us-east-1::lens/serverless</code>. Note that some operations (such as ExportLens and CreateLensShare) are not permitted on Amazon Web Services official lenses.</p>
    /// <p>For custom lenses, this is the lens ARN, such as <code>arn:aws:wellarchitected:us-west-2:123456789012:lens/0123456789abcdef01234567890abcdef</code>.</p>
    /// <p>Each lens is identified by its <code>LensSummary$LensAlias</code>.</p>
    pub fn lens_alias(&self) -> ::std::option::Option<&str> {
        self.lens_alias.as_deref()
    }
    /// <p>A unique case-sensitive string used to ensure that this request is idempotent (executes only once).</p>
    /// <p>You should not reuse the same token for other requests. If you retry a request with the same client request token and the same parameters after the original request has completed successfully, the result of the original request is returned.</p><important>
    /// <p>This token is listed as required, however, if you do not specify it, the Amazon Web Services SDKs automatically generate one for you. If you are not using the Amazon Web Services SDK or the CLI, you must provide this token or the request will fail.</p>
    /// </important>
    pub fn client_request_token(&self) -> ::std::option::Option<&str> {
        self.client_request_token.as_deref()
    }
}
impl UpgradeReviewTemplateLensReviewInput {
    /// Creates a new builder-style object to manufacture [`UpgradeReviewTemplateLensReviewInput`](crate::operation::upgrade_review_template_lens_review::UpgradeReviewTemplateLensReviewInput).
    pub fn builder() -> crate::operation::upgrade_review_template_lens_review::builders::UpgradeReviewTemplateLensReviewInputBuilder {
        crate::operation::upgrade_review_template_lens_review::builders::UpgradeReviewTemplateLensReviewInputBuilder::default()
    }
}

/// A builder for [`UpgradeReviewTemplateLensReviewInput`](crate::operation::upgrade_review_template_lens_review::UpgradeReviewTemplateLensReviewInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpgradeReviewTemplateLensReviewInputBuilder {
    pub(crate) template_arn: ::std::option::Option<::std::string::String>,
    pub(crate) lens_alias: ::std::option::Option<::std::string::String>,
    pub(crate) client_request_token: ::std::option::Option<::std::string::String>,
}
impl UpgradeReviewTemplateLensReviewInputBuilder {
    /// <p>The ARN of the review template.</p>
    /// This field is required.
    pub fn template_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.template_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the review template.</p>
    pub fn set_template_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.template_arn = input;
        self
    }
    /// <p>The ARN of the review template.</p>
    pub fn get_template_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.template_arn
    }
    /// <p>The alias of the lens.</p>
    /// <p>For Amazon Web Services official lenses, this is either the lens alias, such as <code>serverless</code>, or the lens ARN, such as <code>arn:aws:wellarchitected:us-east-1::lens/serverless</code>. Note that some operations (such as ExportLens and CreateLensShare) are not permitted on Amazon Web Services official lenses.</p>
    /// <p>For custom lenses, this is the lens ARN, such as <code>arn:aws:wellarchitected:us-west-2:123456789012:lens/0123456789abcdef01234567890abcdef</code>.</p>
    /// <p>Each lens is identified by its <code>LensSummary$LensAlias</code>.</p>
    /// This field is required.
    pub fn lens_alias(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.lens_alias = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The alias of the lens.</p>
    /// <p>For Amazon Web Services official lenses, this is either the lens alias, such as <code>serverless</code>, or the lens ARN, such as <code>arn:aws:wellarchitected:us-east-1::lens/serverless</code>. Note that some operations (such as ExportLens and CreateLensShare) are not permitted on Amazon Web Services official lenses.</p>
    /// <p>For custom lenses, this is the lens ARN, such as <code>arn:aws:wellarchitected:us-west-2:123456789012:lens/0123456789abcdef01234567890abcdef</code>.</p>
    /// <p>Each lens is identified by its <code>LensSummary$LensAlias</code>.</p>
    pub fn set_lens_alias(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.lens_alias = input;
        self
    }
    /// <p>The alias of the lens.</p>
    /// <p>For Amazon Web Services official lenses, this is either the lens alias, such as <code>serverless</code>, or the lens ARN, such as <code>arn:aws:wellarchitected:us-east-1::lens/serverless</code>. Note that some operations (such as ExportLens and CreateLensShare) are not permitted on Amazon Web Services official lenses.</p>
    /// <p>For custom lenses, this is the lens ARN, such as <code>arn:aws:wellarchitected:us-west-2:123456789012:lens/0123456789abcdef01234567890abcdef</code>.</p>
    /// <p>Each lens is identified by its <code>LensSummary$LensAlias</code>.</p>
    pub fn get_lens_alias(&self) -> &::std::option::Option<::std::string::String> {
        &self.lens_alias
    }
    /// <p>A unique case-sensitive string used to ensure that this request is idempotent (executes only once).</p>
    /// <p>You should not reuse the same token for other requests. If you retry a request with the same client request token and the same parameters after the original request has completed successfully, the result of the original request is returned.</p><important>
    /// <p>This token is listed as required, however, if you do not specify it, the Amazon Web Services SDKs automatically generate one for you. If you are not using the Amazon Web Services SDK or the CLI, you must provide this token or the request will fail.</p>
    /// </important>
    pub fn client_request_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_request_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique case-sensitive string used to ensure that this request is idempotent (executes only once).</p>
    /// <p>You should not reuse the same token for other requests. If you retry a request with the same client request token and the same parameters after the original request has completed successfully, the result of the original request is returned.</p><important>
    /// <p>This token is listed as required, however, if you do not specify it, the Amazon Web Services SDKs automatically generate one for you. If you are not using the Amazon Web Services SDK or the CLI, you must provide this token or the request will fail.</p>
    /// </important>
    pub fn set_client_request_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_request_token = input;
        self
    }
    /// <p>A unique case-sensitive string used to ensure that this request is idempotent (executes only once).</p>
    /// <p>You should not reuse the same token for other requests. If you retry a request with the same client request token and the same parameters after the original request has completed successfully, the result of the original request is returned.</p><important>
    /// <p>This token is listed as required, however, if you do not specify it, the Amazon Web Services SDKs automatically generate one for you. If you are not using the Amazon Web Services SDK or the CLI, you must provide this token or the request will fail.</p>
    /// </important>
    pub fn get_client_request_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_request_token
    }
    /// Consumes the builder and constructs a [`UpgradeReviewTemplateLensReviewInput`](crate::operation::upgrade_review_template_lens_review::UpgradeReviewTemplateLensReviewInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::upgrade_review_template_lens_review::UpgradeReviewTemplateLensReviewInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::upgrade_review_template_lens_review::UpgradeReviewTemplateLensReviewInput {
                template_arn: self.template_arn,
                lens_alias: self.lens_alias,
                client_request_token: self.client_request_token,
            },
        )
    }
}
