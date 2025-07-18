// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetApplicationGrantInput {
    /// <p>Specifies the ARN of the application that contains the grant.</p>
    pub application_arn: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the type of grant.</p>
    pub grant_type: ::std::option::Option<crate::types::GrantType>,
}
impl GetApplicationGrantInput {
    /// <p>Specifies the ARN of the application that contains the grant.</p>
    pub fn application_arn(&self) -> ::std::option::Option<&str> {
        self.application_arn.as_deref()
    }
    /// <p>Specifies the type of grant.</p>
    pub fn grant_type(&self) -> ::std::option::Option<&crate::types::GrantType> {
        self.grant_type.as_ref()
    }
}
impl GetApplicationGrantInput {
    /// Creates a new builder-style object to manufacture [`GetApplicationGrantInput`](crate::operation::get_application_grant::GetApplicationGrantInput).
    pub fn builder() -> crate::operation::get_application_grant::builders::GetApplicationGrantInputBuilder {
        crate::operation::get_application_grant::builders::GetApplicationGrantInputBuilder::default()
    }
}

/// A builder for [`GetApplicationGrantInput`](crate::operation::get_application_grant::GetApplicationGrantInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetApplicationGrantInputBuilder {
    pub(crate) application_arn: ::std::option::Option<::std::string::String>,
    pub(crate) grant_type: ::std::option::Option<crate::types::GrantType>,
}
impl GetApplicationGrantInputBuilder {
    /// <p>Specifies the ARN of the application that contains the grant.</p>
    /// This field is required.
    pub fn application_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the ARN of the application that contains the grant.</p>
    pub fn set_application_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_arn = input;
        self
    }
    /// <p>Specifies the ARN of the application that contains the grant.</p>
    pub fn get_application_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_arn
    }
    /// <p>Specifies the type of grant.</p>
    /// This field is required.
    pub fn grant_type(mut self, input: crate::types::GrantType) -> Self {
        self.grant_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the type of grant.</p>
    pub fn set_grant_type(mut self, input: ::std::option::Option<crate::types::GrantType>) -> Self {
        self.grant_type = input;
        self
    }
    /// <p>Specifies the type of grant.</p>
    pub fn get_grant_type(&self) -> &::std::option::Option<crate::types::GrantType> {
        &self.grant_type
    }
    /// Consumes the builder and constructs a [`GetApplicationGrantInput`](crate::operation::get_application_grant::GetApplicationGrantInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_application_grant::GetApplicationGrantInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_application_grant::GetApplicationGrantInput {
            application_arn: self.application_arn,
            grant_type: self.grant_type,
        })
    }
}
