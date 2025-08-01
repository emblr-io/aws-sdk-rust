// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateServiceInput {
    /// <p>The ID or ARN of the service.</p>
    pub service_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the certificate.</p>
    pub certificate_arn: ::std::option::Option<::std::string::String>,
    /// <p>The type of IAM policy.</p>
    /// <ul>
    /// <li>
    /// <p><code>NONE</code>: The resource does not use an IAM policy. This is the default.</p></li>
    /// <li>
    /// <p><code>AWS_IAM</code>: The resource uses an IAM policy. When this type is used, auth is enabled and an auth policy is required.</p></li>
    /// </ul>
    pub auth_type: ::std::option::Option<crate::types::AuthType>,
}
impl UpdateServiceInput {
    /// <p>The ID or ARN of the service.</p>
    pub fn service_identifier(&self) -> ::std::option::Option<&str> {
        self.service_identifier.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the certificate.</p>
    pub fn certificate_arn(&self) -> ::std::option::Option<&str> {
        self.certificate_arn.as_deref()
    }
    /// <p>The type of IAM policy.</p>
    /// <ul>
    /// <li>
    /// <p><code>NONE</code>: The resource does not use an IAM policy. This is the default.</p></li>
    /// <li>
    /// <p><code>AWS_IAM</code>: The resource uses an IAM policy. When this type is used, auth is enabled and an auth policy is required.</p></li>
    /// </ul>
    pub fn auth_type(&self) -> ::std::option::Option<&crate::types::AuthType> {
        self.auth_type.as_ref()
    }
}
impl UpdateServiceInput {
    /// Creates a new builder-style object to manufacture [`UpdateServiceInput`](crate::operation::update_service::UpdateServiceInput).
    pub fn builder() -> crate::operation::update_service::builders::UpdateServiceInputBuilder {
        crate::operation::update_service::builders::UpdateServiceInputBuilder::default()
    }
}

/// A builder for [`UpdateServiceInput`](crate::operation::update_service::UpdateServiceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateServiceInputBuilder {
    pub(crate) service_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) certificate_arn: ::std::option::Option<::std::string::String>,
    pub(crate) auth_type: ::std::option::Option<crate::types::AuthType>,
}
impl UpdateServiceInputBuilder {
    /// <p>The ID or ARN of the service.</p>
    /// This field is required.
    pub fn service_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID or ARN of the service.</p>
    pub fn set_service_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_identifier = input;
        self
    }
    /// <p>The ID or ARN of the service.</p>
    pub fn get_service_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_identifier
    }
    /// <p>The Amazon Resource Name (ARN) of the certificate.</p>
    pub fn certificate_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.certificate_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the certificate.</p>
    pub fn set_certificate_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.certificate_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the certificate.</p>
    pub fn get_certificate_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.certificate_arn
    }
    /// <p>The type of IAM policy.</p>
    /// <ul>
    /// <li>
    /// <p><code>NONE</code>: The resource does not use an IAM policy. This is the default.</p></li>
    /// <li>
    /// <p><code>AWS_IAM</code>: The resource uses an IAM policy. When this type is used, auth is enabled and an auth policy is required.</p></li>
    /// </ul>
    pub fn auth_type(mut self, input: crate::types::AuthType) -> Self {
        self.auth_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of IAM policy.</p>
    /// <ul>
    /// <li>
    /// <p><code>NONE</code>: The resource does not use an IAM policy. This is the default.</p></li>
    /// <li>
    /// <p><code>AWS_IAM</code>: The resource uses an IAM policy. When this type is used, auth is enabled and an auth policy is required.</p></li>
    /// </ul>
    pub fn set_auth_type(mut self, input: ::std::option::Option<crate::types::AuthType>) -> Self {
        self.auth_type = input;
        self
    }
    /// <p>The type of IAM policy.</p>
    /// <ul>
    /// <li>
    /// <p><code>NONE</code>: The resource does not use an IAM policy. This is the default.</p></li>
    /// <li>
    /// <p><code>AWS_IAM</code>: The resource uses an IAM policy. When this type is used, auth is enabled and an auth policy is required.</p></li>
    /// </ul>
    pub fn get_auth_type(&self) -> &::std::option::Option<crate::types::AuthType> {
        &self.auth_type
    }
    /// Consumes the builder and constructs a [`UpdateServiceInput`](crate::operation::update_service::UpdateServiceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_service::UpdateServiceInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_service::UpdateServiceInput {
            service_identifier: self.service_identifier,
            certificate_arn: self.certificate_arn,
            auth_type: self.auth_type,
        })
    }
}
