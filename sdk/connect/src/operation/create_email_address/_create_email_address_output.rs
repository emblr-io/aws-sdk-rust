// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateEmailAddressOutput {
    /// <p>The identifier of the email address.</p>
    pub email_address_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the email address.</p>
    pub email_address_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateEmailAddressOutput {
    /// <p>The identifier of the email address.</p>
    pub fn email_address_id(&self) -> ::std::option::Option<&str> {
        self.email_address_id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the email address.</p>
    pub fn email_address_arn(&self) -> ::std::option::Option<&str> {
        self.email_address_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateEmailAddressOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateEmailAddressOutput {
    /// Creates a new builder-style object to manufacture [`CreateEmailAddressOutput`](crate::operation::create_email_address::CreateEmailAddressOutput).
    pub fn builder() -> crate::operation::create_email_address::builders::CreateEmailAddressOutputBuilder {
        crate::operation::create_email_address::builders::CreateEmailAddressOutputBuilder::default()
    }
}

/// A builder for [`CreateEmailAddressOutput`](crate::operation::create_email_address::CreateEmailAddressOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateEmailAddressOutputBuilder {
    pub(crate) email_address_id: ::std::option::Option<::std::string::String>,
    pub(crate) email_address_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateEmailAddressOutputBuilder {
    /// <p>The identifier of the email address.</p>
    pub fn email_address_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.email_address_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the email address.</p>
    pub fn set_email_address_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.email_address_id = input;
        self
    }
    /// <p>The identifier of the email address.</p>
    pub fn get_email_address_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.email_address_id
    }
    /// <p>The Amazon Resource Name (ARN) of the email address.</p>
    pub fn email_address_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.email_address_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the email address.</p>
    pub fn set_email_address_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.email_address_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the email address.</p>
    pub fn get_email_address_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.email_address_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateEmailAddressOutput`](crate::operation::create_email_address::CreateEmailAddressOutput).
    pub fn build(self) -> crate::operation::create_email_address::CreateEmailAddressOutput {
        crate::operation::create_email_address::CreateEmailAddressOutput {
            email_address_id: self.email_address_id,
            email_address_arn: self.email_address_arn,
            _request_id: self._request_id,
        }
    }
}
