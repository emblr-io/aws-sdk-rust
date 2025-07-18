// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteTemplateShareInput {
    /// <p>The ID associated with the share.</p>
    pub share_id: ::std::option::Option<::std::string::String>,
    /// <p>The review template ARN.</p>
    pub template_arn: ::std::option::Option<::std::string::String>,
    /// <p>A unique case-sensitive string used to ensure that this request is idempotent (executes only once).</p>
    /// <p>You should not reuse the same token for other requests. If you retry a request with the same client request token and the same parameters after the original request has completed successfully, the result of the original request is returned.</p><important>
    /// <p>This token is listed as required, however, if you do not specify it, the Amazon Web Services SDKs automatically generate one for you. If you are not using the Amazon Web Services SDK or the CLI, you must provide this token or the request will fail.</p>
    /// </important>
    pub client_request_token: ::std::option::Option<::std::string::String>,
}
impl DeleteTemplateShareInput {
    /// <p>The ID associated with the share.</p>
    pub fn share_id(&self) -> ::std::option::Option<&str> {
        self.share_id.as_deref()
    }
    /// <p>The review template ARN.</p>
    pub fn template_arn(&self) -> ::std::option::Option<&str> {
        self.template_arn.as_deref()
    }
    /// <p>A unique case-sensitive string used to ensure that this request is idempotent (executes only once).</p>
    /// <p>You should not reuse the same token for other requests. If you retry a request with the same client request token and the same parameters after the original request has completed successfully, the result of the original request is returned.</p><important>
    /// <p>This token is listed as required, however, if you do not specify it, the Amazon Web Services SDKs automatically generate one for you. If you are not using the Amazon Web Services SDK or the CLI, you must provide this token or the request will fail.</p>
    /// </important>
    pub fn client_request_token(&self) -> ::std::option::Option<&str> {
        self.client_request_token.as_deref()
    }
}
impl DeleteTemplateShareInput {
    /// Creates a new builder-style object to manufacture [`DeleteTemplateShareInput`](crate::operation::delete_template_share::DeleteTemplateShareInput).
    pub fn builder() -> crate::operation::delete_template_share::builders::DeleteTemplateShareInputBuilder {
        crate::operation::delete_template_share::builders::DeleteTemplateShareInputBuilder::default()
    }
}

/// A builder for [`DeleteTemplateShareInput`](crate::operation::delete_template_share::DeleteTemplateShareInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteTemplateShareInputBuilder {
    pub(crate) share_id: ::std::option::Option<::std::string::String>,
    pub(crate) template_arn: ::std::option::Option<::std::string::String>,
    pub(crate) client_request_token: ::std::option::Option<::std::string::String>,
}
impl DeleteTemplateShareInputBuilder {
    /// <p>The ID associated with the share.</p>
    /// This field is required.
    pub fn share_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.share_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID associated with the share.</p>
    pub fn set_share_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.share_id = input;
        self
    }
    /// <p>The ID associated with the share.</p>
    pub fn get_share_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.share_id
    }
    /// <p>The review template ARN.</p>
    /// This field is required.
    pub fn template_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.template_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The review template ARN.</p>
    pub fn set_template_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.template_arn = input;
        self
    }
    /// <p>The review template ARN.</p>
    pub fn get_template_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.template_arn
    }
    /// <p>A unique case-sensitive string used to ensure that this request is idempotent (executes only once).</p>
    /// <p>You should not reuse the same token for other requests. If you retry a request with the same client request token and the same parameters after the original request has completed successfully, the result of the original request is returned.</p><important>
    /// <p>This token is listed as required, however, if you do not specify it, the Amazon Web Services SDKs automatically generate one for you. If you are not using the Amazon Web Services SDK or the CLI, you must provide this token or the request will fail.</p>
    /// </important>
    /// This field is required.
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
    /// Consumes the builder and constructs a [`DeleteTemplateShareInput`](crate::operation::delete_template_share::DeleteTemplateShareInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_template_share::DeleteTemplateShareInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_template_share::DeleteTemplateShareInput {
            share_id: self.share_id,
            template_arn: self.template_arn,
            client_request_token: self.client_request_token,
        })
    }
}
