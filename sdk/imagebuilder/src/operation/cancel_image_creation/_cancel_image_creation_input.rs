// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CancelImageCreationInput {
    /// <p>The Amazon Resource Name (ARN) of the image that you want to cancel creation for.</p>
    pub image_build_version_arn: ::std::option::Option<::std::string::String>,
    /// <p>Unique, case-sensitive identifier you provide to ensure idempotency of the request. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Run_Instance_Idempotency.html">Ensuring idempotency</a> in the <i>Amazon EC2 API Reference</i>.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
}
impl CancelImageCreationInput {
    /// <p>The Amazon Resource Name (ARN) of the image that you want to cancel creation for.</p>
    pub fn image_build_version_arn(&self) -> ::std::option::Option<&str> {
        self.image_build_version_arn.as_deref()
    }
    /// <p>Unique, case-sensitive identifier you provide to ensure idempotency of the request. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Run_Instance_Idempotency.html">Ensuring idempotency</a> in the <i>Amazon EC2 API Reference</i>.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl CancelImageCreationInput {
    /// Creates a new builder-style object to manufacture [`CancelImageCreationInput`](crate::operation::cancel_image_creation::CancelImageCreationInput).
    pub fn builder() -> crate::operation::cancel_image_creation::builders::CancelImageCreationInputBuilder {
        crate::operation::cancel_image_creation::builders::CancelImageCreationInputBuilder::default()
    }
}

/// A builder for [`CancelImageCreationInput`](crate::operation::cancel_image_creation::CancelImageCreationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CancelImageCreationInputBuilder {
    pub(crate) image_build_version_arn: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
}
impl CancelImageCreationInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the image that you want to cancel creation for.</p>
    /// This field is required.
    pub fn image_build_version_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.image_build_version_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the image that you want to cancel creation for.</p>
    pub fn set_image_build_version_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.image_build_version_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the image that you want to cancel creation for.</p>
    pub fn get_image_build_version_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.image_build_version_arn
    }
    /// <p>Unique, case-sensitive identifier you provide to ensure idempotency of the request. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Run_Instance_Idempotency.html">Ensuring idempotency</a> in the <i>Amazon EC2 API Reference</i>.</p>
    /// This field is required.
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Unique, case-sensitive identifier you provide to ensure idempotency of the request. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Run_Instance_Idempotency.html">Ensuring idempotency</a> in the <i>Amazon EC2 API Reference</i>.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>Unique, case-sensitive identifier you provide to ensure idempotency of the request. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Run_Instance_Idempotency.html">Ensuring idempotency</a> in the <i>Amazon EC2 API Reference</i>.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Consumes the builder and constructs a [`CancelImageCreationInput`](crate::operation::cancel_image_creation::CancelImageCreationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::cancel_image_creation::CancelImageCreationInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::cancel_image_creation::CancelImageCreationInput {
            image_build_version_arn: self.image_build_version_arn,
            client_token: self.client_token,
        })
    }
}
